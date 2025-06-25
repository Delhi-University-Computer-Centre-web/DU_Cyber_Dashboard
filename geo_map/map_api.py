# geo_map/map_api.py

from flask import Blueprint, jsonify
from models import LogEntry

geo_map_api = Blueprint("geo_map_api", __name__)

@geo_map_api.route("/api/geoip")
def geoip_data():
    entries = LogEntry.query.filter(LogEntry.threat.isnot(None)).all()

    data = []
    for entry in entries:
        if entry.geo_country and entry.geo_city:
            data.append({
                "ip": entry.ip,
                "city": entry.geo_city,
                "country": entry.geo_country,
                "timestamp": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "threat": entry.threat
            })
    return jsonify(data)
