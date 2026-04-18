#!/usr/bin/env python3
from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
RESET = "\033[0m"

DEFAULT_DUMMY_FILE = Path("/tmp/tm-verify-dummy.json")
BPF_FS = "/sys/fs/bpf"
BINARY_NAME = "traffic-manager"


class BenchmarkError(RuntimeError):
    pass


@dataclass(frozen=True)
class BenchmarkConfig:
    namespace: str
    siege_pod: str
    connections: int
    duration: str
    dummy_service_count: int
    rule_bloat: bool
    dummy_manifest: Path
    binary_name: str = BINARY_NAME

    @property
    def local_binary(self) -> Path:
        return Path("bin") / f"{self.binary_name}-linux"

    @property
    def remote_binary(self) -> str:
        return f"/usr/local/bin/{self.binary_name}"

    @property
    def bpf_map_path(self) -> str:
        return f"{BPF_FS}/sock_ops_map"


@dataclass(frozen=True)
class BenchmarkResult:
    phase: str
    qps: float | None

    @property
    def display_qps(self) -> str:
        return f"{self.qps:.2f}" if self.qps is not None else "n/a"


class Logger:
    def info(self, message: str) -> None:
        print(f"{GREEN}[INFO] {message}{RESET}", flush=True)

    def warn(self, message: str) -> None:
        print(f"{YELLOW}[WARN] {message}{RESET}", flush=True)

    def error(self, message: str) -> None:
        print(f"{RED}[ERROR] {message}{RESET}", file=sys.stderr, flush=True)


class CommandRunner:
    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        capture_output: bool = False,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(args),
            check=check,
            text=True,
            capture_output=capture_output,
            env=env,
            timeout=timeout,
        )

    def minikube_ssh(
        self,
        remote_command: str,
        *,
        check: bool = True,
        capture_output: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            ["minikube", "ssh", remote_command],
            check=check,
            capture_output=capture_output,
        )


class MinikubeBenchmark:
    def __init__(
        self,
        config: BenchmarkConfig,
        runner: CommandRunner | None = None,
        logger: Logger | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.log = logger or Logger()
        self._cleanup_done = False

    def run(self) -> int:
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        self._check_environment()
        atexit.register(self.cleanup)
        self._build_linux_binary()
        self._deploy_workloads()
        target_url = self._resolve_target_url()
        self._prepare_rule_bloat()

        baseline = self._run_siege(target_url, "Baseline (kube-proxy)")

        self._start_traffic_manager()
        self._wait_for_bpf_ready(target_url)

        ebpf = self._run_siege(target_url, "eBPF (Sockops Bypass)")
        self._print_summary([baseline, ebpf])
        return 0

    def cleanup(self) -> None:
        if self._cleanup_done:
            return
        self._cleanup_done = True

        self.log.warn("Cleaning up resources...")
        self._stop_remote_binary()
        self.runner.minikube_ssh(
            f"sudo rm -rf {shlex.quote(self.config.bpf_map_path)} || true",
            check=False,
            capture_output=True,
        )

        if self.config.rule_bloat:
            self.runner.run(
                [
                    "kubectl",
                    "delete",
                    "service",
                    "-l",
                    "dummy=true",
                    "-n",
                    self.config.namespace,
                    "--wait=false",
                ],
                check=False,
                capture_output=True,
            )
            self.config.dummy_manifest.unlink(missing_ok=True)

    def _handle_signal(self, signum: int, _frame: object) -> None:
        self.log.warn(f"Received signal {signum}, exiting...")
        raise SystemExit(1)

    def _check_environment(self) -> None:
        self.log.info("Checking minikube status")
        result = self.runner.run(
            ["minikube", "status"],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise BenchmarkError("Minikube is not running.")

    def _build_linux_binary(self) -> None:
        self.log.info("Building linux binary")
        build_env = os.environ.copy()
        build_env.update({"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"})
        self.runner.run(
            [
                "go",
                "build",
                "-o",
                str(self.config.local_binary),
                "main.go",
            ],
            env=build_env,
        )

    def _deploy_workloads(self) -> None:
        self.log.info("Deploying Traffic Manager binary and benchmark workloads")
        self._stop_remote_binary()
        self.runner.run(
            [
                "minikube",
                "cp",
                str(self.config.local_binary),
                f"/tmp/{self.config.binary_name}",
            ]
        )
        self.runner.minikube_ssh(
            "sudo mv "
            f"{shlex.quote(f'/tmp/{self.config.binary_name}')} "
            f"{shlex.quote(self.config.remote_binary)} "
            f"&& sudo chmod +x {shlex.quote(self.config.remote_binary)}",
        )

        self._kubectl_apply(Path("k8s/deployment-example.yaml"))
        self._kubectl_apply(Path("k8s/siege-pod.yaml"))
        self.runner.run(
            [
                "kubectl",
                "wait",
                "--for=condition=Ready",
                f"pod/{self.config.siege_pod}",
                "-n",
                self.config.namespace,
                "--timeout=120s",
            ],
            capture_output=True,
        )
        self.runner.run(
            [
                "kubectl",
                "rollout",
                "status",
                "deploy/sisyphe-deployment",
                "-n",
                self.config.namespace,
                "--timeout=120s",
            ],
            check=False,
            capture_output=True,
        )

    def _resolve_target_url(self) -> str:
        service_ip = self.runner.run(
            [
                "kubectl",
                "get",
                "svc",
                "sisyphe",
                "-n",
                self.config.namespace,
                "-o",
                "jsonpath={.spec.clusterIP}",
            ],
            capture_output=True,
        ).stdout.strip()
        if not service_ip:
            raise BenchmarkError("Service 'sisyphe' not found.")

        target_url = f"http://{service_ip}:80"
        self.log.info(f"Target Service URL resolved: {target_url}")
        return target_url

    def _prepare_rule_bloat(self) -> None:
        if not self.config.rule_bloat:
            return

        self.log.info(
            f"Creating {self.config.dummy_service_count} dummy services "
            "for rule bloat test"
        )
        write_dummy_services_manifest(
            self.config.dummy_manifest,
            self.config.namespace,
            self.config.dummy_service_count,
        )
        self.runner.run(
            ["kubectl", "apply", "-f", str(self.config.dummy_manifest)],
            capture_output=True,
        )
        self.log.info("Waiting 20s for kube-proxy rules (iptables/ipvs) convergence...")
        time.sleep(20)

    def _start_traffic_manager(self) -> None:
        self.log.info("Starting eBPF Traffic Manager")
        self.runner.minikube_ssh(
            f"mount | grep -q 'type bpf' || sudo mount -t bpf bpf {shlex.quote(BPF_FS)}"
        )
        self.runner.minikube_ssh(f"sudo rm -rf {shlex.quote(self.config.bpf_map_path)}")
        self.runner.minikube_ssh(
            "sudo sh -c "
            + shlex.quote(
                "nohup "
                f"{self.config.remote_binary} "
                "-kubeconfig=/etc/kubernetes/admin.conf "
                f">/tmp/{self.config.binary_name}.log 2>&1 &"
            )
        )

    def _wait_for_bpf_ready(self, target_url: str) -> None:
        service_ip = target_url.removeprefix("http://").split(":", maxsplit=1)[0]
        if not wait_condition(
            "Waiting for eBPF Map pinning",
            lambda: self.runner.minikube_ssh(
                f"test -d {shlex.quote(self.config.bpf_map_path)}",
                check=False,
            ).returncode
            == 0,
            timeout_seconds=30,
        ):
            raise BenchmarkError("eBPF map not pinned.")

        check_command = (
            f"sudo {shlex.quote(self.config.remote_binary)} "
            f"-check-service-ip={shlex.quote(service_ip)} "
            "-check-service-port=80 >/dev/null 2>&1"
        )
        if not wait_condition(
            "Syncing Service IP to BPF Map",
            lambda: self.runner.minikube_ssh(check_command, check=False).returncode
            == 0,
            timeout_seconds=60,
        ):
            raise BenchmarkError("Service not synced.")

        time.sleep(5)

    def _run_siege(self, url: str, phase: str) -> BenchmarkResult:
        self.log.info(f"Running Siege Benchmark: [{phase}]")
        self._exec_siege(url, connections=50, duration="5S")
        result = self._exec_siege(
            url,
            connections=self.config.connections,
            duration=self.config.duration,
        )
        output = "\n".join([result.stdout or "", result.stderr or ""])
        return BenchmarkResult(phase=phase, qps=parse_qps(output))

    def _exec_siege(
        self,
        url: str,
        *,
        connections: int,
        duration: str,
    ) -> subprocess.CompletedProcess[str]:
        timeout_seconds = siege_timeout_seconds(duration)
        args = [
            "kubectl",
            "exec",
            "-n",
            self.config.namespace,
            self.config.siege_pod,
            "--",
            "timeout",
            "-k",
            "5",
            str(timeout_seconds),
            "siege",
            "-c",
            str(connections),
            "-t",
            duration,
            "-b",
            url,
        ]

        try:
            return self.runner.run(
                args,
                check=False,
                capture_output=True,
                timeout=timeout_seconds + 10,
            )
        except subprocess.TimeoutExpired as exc:
            self.log.warn(
                f"Siege timed out after {timeout_seconds}s "
                f"(connections={connections}, duration={duration})"
            )
            self._kill_siege_processes()
            return subprocess.CompletedProcess(
                args,
                124,
                stdout=timeout_output_to_text(exc.stdout),
                stderr=timeout_output_to_text(exc.stderr),
            )

    def _kubectl_apply(self, manifest: Path) -> None:
        self.runner.run(
            [
                "kubectl",
                "apply",
                "--validate=false",
                "--request-timeout=0",
                "-f",
                str(manifest),
                "-n",
                self.config.namespace,
            ],
            capture_output=True,
        )

    def _stop_remote_binary(self) -> None:
        pattern = process_match_pattern(self.config.binary_name)
        self.runner.minikube_ssh(
            f"sudo pkill -f {shlex.quote(pattern)} || true",
            check=False,
            capture_output=True,
        )

    def _kill_siege_processes(self) -> None:
        self.runner.run(
            [
                "kubectl",
                "exec",
                "-n",
                self.config.namespace,
                self.config.siege_pod,
                "--",
                "sh",
                "-c",
                (
                    "for pid in $(ps -o pid= -o comm= | "
                    "awk '$2 == \"siege\" {print $1}'); "
                    'do kill -9 "$pid" 2>/dev/null || true; done'
                ),
            ],
            check=False,
            capture_output=True,
        )

    def _print_summary(self, results: Sequence[BenchmarkResult]) -> None:
        print(f"\n{GREEN}================ SUMMARY ================{RESET}")
        print(f"{'Mode':<25} | {'Trans/sec (QPS)':<15}")
        print("-----------------------------------------")
        for result in results:
            print(f"{result.phase:<25} | {result.display_qps:<15}")

        baseline, ebpf = results
        if baseline.qps and ebpf.qps is not None:
            delta = ((ebpf.qps - baseline.qps) / baseline.qps) * 100
            print(f"\nPerformance Delta: {delta:.2f}%")

        print(f"{GREEN}========================================={RESET}")


def process_match_pattern(binary_name: str) -> str:
    if not binary_name:
        return ""
    return f"[{binary_name[0]}]{binary_name[1:]}"


def wait_condition(
    message: str,
    predicate: Callable[[], bool],
    *,
    timeout_seconds: int,
) -> bool:
    print(f"{message} ", end="", flush=True)
    for _ in range(timeout_seconds):
        if predicate():
            print(" [OK]")
            return True
        print(".", end="", flush=True)
        time.sleep(1)
    print(" [TIMEOUT]")
    return False


def write_dummy_services_manifest(path: Path, namespace: str, count: int) -> None:
    manifest = {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": f"tm-dummy-svc-{index}",
                    "namespace": namespace,
                    "labels": {"dummy": "true"},
                },
                "spec": {
                    "ports": [{"port": 80, "targetPort": 80}],
                    "selector": {"app": "non-existent"},
                },
            }
            for index in range(1, count + 1)
        ],
    }
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def parse_qps(siege_output: str) -> float | None:
    match = re.search(r'"transaction_rate"\s*:\s*([0-9.]+)', siege_output)
    if match:
        return float(match.group(1))

    match = re.search(r"Transaction rate:\s+([0-9.]+)", siege_output)
    return float(match.group(1)) if match else None


def siege_timeout_seconds(duration: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([SMHsmh]?)\s*", duration)
    if not match:
        return 60

    value = int(match.group(1))
    unit = match.group(2).upper() or "S"
    multiplier = {"S": 1, "M": 60, "H": 3600}[unit]
    return max(10, value * multiplier + 30)


def timeout_output_to_text(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, str):
        return output
    return bytes(output).decode("utf-8", errors="replace")


def env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise BenchmarkError(f"{name} must be an integer") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark traffic-manager on minikube"
    )
    parser.add_argument(
        "--namespace",
        default=os.getenv("NAMESPACE", "default"),
        help="Kubernetes namespace to use (default: %(default)s)",
    )
    parser.add_argument(
        "--siege-pod",
        default=os.getenv("SIEGE_POD", "siege"),
        help="Pod name that contains the siege binary (default: %(default)s)",
    )
    parser.add_argument(
        "--connections",
        type=int,
        default=env_int("CONNECTIONS", 200),
        help="Siege concurrent connections (default: %(default)s)",
    )
    parser.add_argument(
        "--duration",
        default=os.getenv("DURATION", "15S"),
        help="Siege duration, for example 15S or 1M (default: %(default)s)",
    )
    parser.add_argument(
        "--dummy-service-count",
        type=int,
        default=env_int("DUMMY_SVC_COUNT", 1000),
        help="Number of dummy services for --rule-bloat (default: %(default)s)",
    )
    parser.add_argument(
        "--dummy-manifest",
        type=Path,
        default=DEFAULT_DUMMY_FILE,
        help="Temporary dummy service manifest path (default: %(default)s)",
    )
    parser.add_argument(
        "--rule-bloat",
        action="store_true",
        help="Create many dummy services to test kube-proxy rule bloat",
    )
    return parser


def parse_args(argv: Sequence[str] | None = None) -> BenchmarkConfig:
    args = build_parser().parse_args(argv)
    if args.connections <= 0:
        raise BenchmarkError("--connections must be greater than 0")
    if args.dummy_service_count <= 0:
        raise BenchmarkError("--dummy-service-count must be greater than 0")

    return BenchmarkConfig(
        namespace=args.namespace,
        siege_pod=args.siege_pod,
        connections=args.connections,
        duration=args.duration,
        dummy_service_count=args.dummy_service_count,
        rule_bloat=args.rule_bloat,
        dummy_manifest=args.dummy_manifest,
    )


def main(argv: Sequence[str] | None = None) -> int:
    logger = Logger()
    try:
        return MinikubeBenchmark(parse_args(argv), logger=logger).run()
    except (BenchmarkError, subprocess.CalledProcessError) as exc:
        logger.error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
