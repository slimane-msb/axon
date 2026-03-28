#!/bin/bash
# axon_bench.sh - Performance & Resource Benchmark

# --- DYNAMIC CONFIGURATION ---
IF_FAST=$1
if [[ "$IF_FAST" == "-f" ]]; then
    TEST_URL="http://10.192.70.139:8000/biancarossosalcedo/Downloads/100MB.bin"
    RUNS=4
    SIZE_LABEL="100MB (Fast Check)"
else
    TEST_URL="https://nbg1-speed.hetzner.com/1GB.bin"
    RUNS=10
    SIZE_LABEL="1GB (Deep Stress Test)"
fi

TEMP_FILE="axon_test.bin"

# Check for 'bc' dependency
if ! command -v bc &> /dev/null; then echo "Install 'bc' first: sudo apt install bc"; exit 1; fi

echo "=========================================================="
echo "MODE: $SIZE_LABEL"
echo "SESSIONS: $RUNS Iterations"
echo "=========================================================="

t_mbps=0; t_lat=0; t_cpu=0; t_ram=0

for i in $(seq 1 $RUNS); do
    echo -n "[Run $i/$RUNS] Testing... "

    # 1. Start Monitors
    ping -c 3 10.192.70.139 > p.tmp &
    vmstat 1 > v.tmp &
    VPID=$!
    ram_start=$(free -m | awk '/Mem:/ {print $3}')

    # 2. THE DOWNLOAD
    # -L follows redirects, -s is silent, -w outputs speed
    speed_bps=$(curl -L -o $TEMP_FILE -s -w "%{speed_download}\n" "$TEST_URL")
    
    # 3. Stop monitors and cleanup
    kill $VPID 2>/dev/null
    ram_end=$(free -m | awk '/Mem:/ {print $3}')
    rm -f $TEMP_FILE

    # 4. CALCULATIONS
    mbps=$(echo "scale=2; $speed_bps * 8 / 1048576" | bc)
    
    # Latency (Avg RTT)
    lat=$(grep 'rtt' p.tmp | cut -d'/' -f5 | awk '{print $1}')
    [ -z "$lat" ] && lat=0
    
    # CPU usage (Calculated as 100 - idle time)
    cpu_idle=$(awk '{if(NR>2) sum+=$15; count++} END {if(count>0) print sum/count; else print 100}' v.tmp)
    cpu_usage=$(echo "100 - $cpu_idle" | bc)
    
    # RAM Delta (MB)
    ram_diff=$(echo "$ram_end - $ram_start" | bc)
    if (( $(echo "$ram_diff < 0" | bc -l) )); then ram_diff=0; fi

    echo "$mbps Mbps | CPU: $cpu_usage% | RAM: +${ram_diff}MB | Lat: ${lat}ms"

    # Summing totals
    t_mbps=$(echo "$t_mbps + $mbps" | bc)
    t_lat=$(echo "$t_lat + $lat" | bc)
    t_cpu=$(echo "$t_cpu + $cpu_usage" | bc)
    t_ram=$(echo "$t_ram + $ram_diff" | bc)
done

# --- FINAL AVERAGING ---
echo -e "\n=========================================================="
echo "FINAL AVERAGES FOR THIS SCENARIO:"
echo "----------------------------------------------------------"
echo ">> Avg Throughput: $(echo "scale=2; $t_mbps / $RUNS" | bc) Mbps"
echo ">> Avg Latency:    $(echo "scale=2; $t_lat / $RUNS" | bc) ms"
echo ">> Avg System CPU: $(echo "scale=2; $t_cpu / $RUNS" | bc) %"
echo ">> Avg RAM Delta:  $(echo "scale=2; $t_ram / $RUNS" | bc) MB"
echo "=========================================================="

rm -f p.tmp v.tmp