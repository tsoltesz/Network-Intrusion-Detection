import pandas as pd
import random
from datetime import datetime, timedelta



def random_timestamp(start_date: str, end_date: str, format: str = "%Y-%m-%d %H:%M:%S"):
    start = datetime.strptime(start_date, format)
    end = datetime.strptime(end_date, format)
    random_time = start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))
    return random_time.strftime(format)

def get_traffic(org,   num=1500, t="attack"):
    nb15 = pd.read_csv('csv\\unsw_nb15.csv')
    nb15 = nb15[['ct_src_dport_ltm', 'ct_dst_sport_ltm', 'proto', 'sbytes', 'attack_cat','state']]
    if t != "attack":
        traffic = nb15[nb15['attack_cat'] == 'Normal'].sample(n=num)
    else:
        traffic = nb15[nb15['attack_cat'] != 'Normal'].sample(n=num)

    traffic['id'] = [i for i in range(len(org), len(org) + len(traffic))]
    traffic['timestamp'] = [random_timestamp("2024-10-14 00:00:00","2024-11-20 00:00:00") for i in range (len(traffic))]
    traffic['src_ip'] = ['192.168.0.138' for i in range (len(traffic))]
    traffic['dst_ip'] = ['192.168.0.100' for i in range (len(traffic))]
    traffic['message_content'] = [random.choice(org['message_content']) for i in range (len(traffic))]
    traffic['label'] = [t for i in range (len(traffic))]

    traffic['src_port'] = traffic['ct_src_dport_ltm']
    traffic['dst_port'] = traffic['ct_dst_sport_ltm']
    traffic['protocol'] = traffic['proto']
    traffic['length'] = traffic['sbytes']
    traffic['flag'] = traffic['state']

    traffic = traffic[['id','timestamp','src_ip','src_port','dst_ip','dst_port','message_content','protocol','length','label']]

    return pd.DataFrame(traffic)


original_data = pd.read_csv('csv\\traffic.csv')
original_data['label'] = 'normal'

attacks = get_traffic(original_data,2500)

augmented_data = pd.concat([original_data, attacks], ignore_index=True)

output_path = 'csv\\augmented_with_unsw_nb15_attacks.csv'
augmented_data.to_csv(output_path, index=False)

normals = get_traffic(original_data,1000,t= "normal")
augmented_data = pd.concat([augmented_data, normals], ignore_index=True)

output_path = 'csv\\augmented_with_unsw_nb15.csv'
augmented_data.to_csv(output_path, index=False)

