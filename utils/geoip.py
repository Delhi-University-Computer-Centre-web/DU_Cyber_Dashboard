# utils/geoip.py
import os
import geoip2.database

GEOIP_DB_PATH = os.path.join("utils", "GeoLite2-City.mmdb")

def get_ip_location(ip_address):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip_address)
            city = response.city.name or "Unknown City"
            country = response.country.name or "Unknown Country"
            return f"{city}, {country}"
    except Exception as e:
        print(f"[GeoIP Error] IP: {ip_address} -> {str(e)}")
        return "Unknown Location"
