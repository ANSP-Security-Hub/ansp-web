#!../venv/bin/python3
import speedtest


def get_network_speed():
    '''
    return a dictionary -> download_speed { 'speed' : speed }
    *this code takes from 15 to 25 seconds
    '''
    st = speedtest.Speedtest()
    st.get_best_server()
    download_speed = st.download() / 1024 / 1024
    speed_info = {'speed':download_speed}
    return speed_info


def main():
    download_speed = get_network_speed()
    print(download_speed)

if __name__ == '__main__':
    main()
