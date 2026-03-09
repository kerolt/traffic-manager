#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-default}"
SIEGE_POD="${SIEGE_POD:-siege}"
CONNECTIONS="${CONNECTIONS:-200}"
DURATION="${DURATION:-15S}"
DUMMY_SVC_COUNT="${DUMMY_SVC_COUNT:-1000}"
DUMMY_FILE="/tmp/tm-verify-dummy.yml"
BINARY_NAME="traffic-manager"
BPF_FS="/sys/fs/bpf"

# 测试 iptables/ipvs 规则数量爆炸时产生的网络性能衰减
RULE_BLOAT=0
if [[ "${1:-}" == "--rule-bloat" ]]; then
	RULE_BLOAT=1
fi

# ==========================================
# 输出颜色配置
# ==========================================
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_RED='\033[0;31m'
readonly C_RESET='\033[0m'

# ==========================================
# 日志和工具函数
# ==========================================
log_info() { echo -e "${C_GREEN}[INFO] $1${C_RESET}"; }
log_warn() { echo -e "${C_YELLOW}[WARN] $1${C_RESET}"; }
log_err() {
	echo -e "${C_RED}[ERROR] $1${C_RESET}" >&2
	exit 1
}

m_ssh() { minikube ssh "$@" 2>/dev/null; }

wait_condition() {
	local msg=$1
	local cmd=$2
	local timeout=${3:-30}
	echo -n "$msg "
	for ((i = 1; i <= timeout; i++)); do
		if eval "$cmd"; then
			echo " [OK]"
			return 0
		fi
		echo -n "."
		sleep 1
	done
	echo " [TIMEOUT]"
	return 1
}

# ==========================================
# 终止信号处理和资源清理
# ==========================================
cleanup() {
	log_warn "Cleaning up resources..."
	m_ssh "sudo pkill -f ${BINARY_NAME} || true"
	m_ssh "sudo rm -rf ${BPF_FS}/sock_ops_map || true"
	# 同步更新这里的判断条件
	if [[ $RULE_BLOAT -eq 1 ]]; then
		kubectl delete service -l dummy=true -n "$NAMESPACE" --wait=false >/dev/null 2>&1 || true
		rm -f "${DUMMY_FILE}"
	fi
}
trap cleanup EXIT

# ==========================================
# 环境检查和构建
# ==========================================
log_info "1. Environment Check & Build"
minikube status >/dev/null 2>&1 || log_err "Minikube is not running."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "bin/${BINARY_NAME}-linux" main.go

log_info "2. Deploying Traffic Manager & Workloads"
m_ssh "sudo pkill -f ${BINARY_NAME} || true"
minikube cp "bin/${BINARY_NAME}-linux" "/tmp/${BINARY_NAME}"
m_ssh "sudo mv /tmp/${BINARY_NAME} /usr/local/bin/ && sudo chmod +x /usr/local/bin/${BINARY_NAME}"

kubectl apply --validate=false --request-timeout=0 -f k8s/deployment-example.yaml -n "$NAMESPACE" >/dev/null
kubectl apply --validate=false --request-timeout=0 -f k8s/siege-pod.yaml -n "$NAMESPACE" >/dev/null

kubectl wait --for=condition=Ready pod/"$SIEGE_POD" -n "$NAMESPACE" --timeout=120s >/dev/null
kubectl rollout status deploy/sisyphe-deployment -n "$NAMESPACE" --timeout=120s >/dev/null || true

SVC_IP=$(kubectl get svc sisyphe -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
[[ -z "$SVC_IP" ]] && log_err "Service 'sisyphe' not found."
URL="http://${SVC_IP}:80"
log_info "Target Service URL resolved: $URL"

# ==========================================
# 测试规则数量爆炸时产生的网络性能衰减
# ==========================================
if [[ $RULE_BLOAT -eq 1 ]]; then
	log_info "3. Generating ${DUMMY_SVC_COUNT} dummy services for rule bloat test"
	seq 1 "$DUMMY_SVC_COUNT" | awk -v ns="$NAMESPACE" '
        BEGIN { print "apiVersion: v1\nkind: List\nitems:" }
        {
            print "- apiVersion: v1\n  kind: Service\n  metadata:\n    name: tm-dummy-svc-"$1
            print "    namespace: "ns"\n    labels:\n      dummy: \"true\"\n  spec:\n    ports:"
            print "    - port: 80\n      targetPort: 80\n    selector:\n      app: non-existent"
        }' >"${DUMMY_FILE}"

	kubectl apply -f "${DUMMY_FILE}" >/dev/null
	log_info "Waiting 20s for kube-proxy rules (iptables/ipvs) convergence..."
	sleep 20
fi

# ==========================================
# 基准测试 - kube-proxy
# ==========================================
run_siege() {
	local phase=$1
	log_info "Running Siege Benchmark: [$phase]"
	kubectl exec -n "$NAMESPACE" "$SIEGE_POD" -- siege -c 50 -t 5S -b "$URL" >/dev/null 2>&1 || true
	local output
	output=$(kubectl exec -n "$NAMESPACE" "$SIEGE_POD" -- siege -c "$CONNECTIONS" -t "$DURATION" -b "$URL" 2>&1)
	echo "$output" | sed -n -E 's/.*Transaction rate:[[:space:]]+([0-9.]+).*/\1/p' | head -n1 || echo "0"
}

BASELINE_QPS=$(run_siege "Baseline (kube-proxy)")

log_info "4. Starting eBPF Traffic Manager"
m_ssh "mount | grep -q 'type bpf' || sudo mount -t bpf bpf ${BPF_FS}"
m_ssh "sudo rm -rf ${BPF_FS}/sock_ops_map"
m_ssh "sudo sh -c 'nohup /usr/local/bin/${BINARY_NAME} -kubeconfig=/etc/kubernetes/admin.conf >/tmp/${BINARY_NAME}.log 2>&1 &'"

wait_condition "Waiting for eBPF Map pinning" "m_ssh 'test -d ${BPF_FS}/sock_ops_map'" 30 || log_err "eBPF map not pinned."
wait_condition "Syncing Service IP to BPF Map" "m_ssh 'sudo /usr/local/bin/${BINARY_NAME} -check-service-ip=${SVC_IP} -check-service-port=80 >/dev/null 2>&1'" 60 || log_err "Service not synced."
sleep 5

EBPF_QPS=$(run_siege "eBPF (Sockops Bypass)")

# ==========================================
# 结果汇总
# ==========================================
echo -e "\n${C_GREEN}================ SUMMARY ================${C_RESET}"
printf "%-25s | %-15s\n" "Mode" "Trans/sec (QPS)"
echo "-----------------------------------------"
printf "%-25s | %-15s\n" "Baseline (kube-proxy)" "$BASELINE_QPS"
printf "%-25s | %-15s\n" "eBPF (Sockops)" "$EBPF_QPS"

awk -v b="$BASELINE_QPS" -v e="$EBPF_QPS" 'BEGIN {
    if (b > 0) printf "\nPerformance Delta: %.2f%%\n", ((e-b)/b)*100
}'
echo -e "${C_GREEN}=========================================${C_RESET}"
