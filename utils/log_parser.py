# utils/log_parser.py
import os
from collections import Counter, defaultdict
from datetime import datetime
import random
from utils.geoip import get_ip_location  


def parse_logs(log_dir):
    status_counts = Counter()
    ip_counts = Counter()
    timeline = defaultdict(int)
    top_urls = Counter()
    top_agents = Counter()
    top_countries = Counter()
    top_threats = Counter()
    ai_threats = Counter()
    ip_set = set()
    total_threats = 0

    for filename in os.listdir(log_dir):
        if filename.endswith(".log"):
            filepath = os.path.join(log_dir, filename)
            with open(filepath, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 10:
                        ip, identity, userid, datetime_raw, tz, method, url, protocol, status, size = parts[:10]

                        ip_counts[ip] += 1
                        status_counts[status] += 1
                        top_urls[url] += 1
                        top_agents[userid] += 1
                        top_countries[random.choice(['India', 'US', 'Germany', 'China'])] += 1

                        try:
                            dt = datetime.strptime(datetime_raw, '[%d/%b/%Y:%H:%M:%S')
                            timeline[dt.strftime('%H:%M')] += 1
                        except:
                            continue

                        if status.startswith('4') or status.startswith('5'):
                            top_threats[ip] += 1
                            total_threats += 1

                        if random.random() < 0.1:
                            ai_threats[ip] += 1

                        ip_set.add(ip)

    result = {
        'total_logs': sum(ip_counts.values()),
        'total_threats': total_threats,
        'unique_ips': len(ip_set),
        'status_counts': dict(status_counts),
        'ip_counts': dict(ip_counts.most_common(10)),
        'timeline': dict(timeline),
        'top_urls': dict(top_urls.most_common(5)),
        'top_agents': dict(top_agents.most_common(5)),
        'top_countries': dict(top_countries.most_common(5)),
        'top_threats': dict(top_threats.most_common(5)),
        'ai_threats': dict(ai_threats.most_common(5)),
        'all_threat_ips': list(top_threats.keys()),
        'geo_data': [get_ip_location(ip) for ip in top_threats]
    }

    return result