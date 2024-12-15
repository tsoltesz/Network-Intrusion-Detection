import pandas as pd
import random
from datetime import datetime, timedelta


def random_timestamp(start_date: str, end_date: str, format: str = "%Y-%m-%d %H:%M:%S"):
    start = datetime.strptime(start_date, format)
    end = datetime.strptime(end_date, format)
    random_time = start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))
    return random_time.strftime(format)

def generate_synthetic_attacks(data, num_attacks=1500):
    data = pd.DataFrame(data)
    synthetic_data = []
    ips = data['dst_ip'].unique()
    unique_ports = range(min(data['src_port']), (max(data['src_port'])))
    protocols = data['protocol'].unique()
    
    for _ in range(num_attacks):

        if random.random() < 0.3:  
            length = random.randint(min(data['length']), (min(data['length']))) + random.randint(100, 500)
        else:
            length = random.randint(min(data['length']), (min(data['length']))) 
        
        protocol = random.choice(protocols)
        flag = ''
        if (protocol=="TCP"):
            flag = random.choice(['SYN', 'ACK', 'FIN'])
        filtered_data = data[data['flags'] == flag]

        if not filtered_data.empty:
            src_port = random.choice(filtered_data['src_port'].dropna().tolist())
            dst_port = random.choice(filtered_data['dst_port'].dropna().tolist())
        else:
            src_port = random.choice(unique_ports)
            dst_port = random.choice(unique_ports)

        synthetic_data.append({
            'id': len(data) + len(synthetic_data) + 1,
            'timestamp': random_timestamp("2024-10-14 00:00:00","2024-11-20 00:00:00"),
            'src_ip': '192.168.0.138',  
            'dst_ip': '192.168.0.100', 
            'protocol': protocol,
            'src_port': src_port, 
            'dst_port': dst_port,  
            'length': length,
            'flags': flag, 
            'message_content': random.choice(data['message_content']),
            'label': 'attack'  
        })

    return pd.DataFrame(synthetic_data)


original_data = pd.read_csv('csv\\traffic.csv')

original_data['label'] = 'normal'

synthetic_attacks = generate_synthetic_attacks(original_data)

augmented_data = pd.concat([original_data, synthetic_attacks], ignore_index=True)

augmented_data.to_csv('csv\\augmented_traffic_with_synthetic_attacks.csv', index=False)

