# pysnort test module
# (Good as a tutorial)

# import pysnort module
import pysnort

import time


# some dates
now =  time.gmtime(time.time())
lastweek = time.gmtime(time.time() - 604800)

# create a mysqlLog instance
pys = pysnort.mysqlLog()

# creates connection object.
# 'conn' has to be passed to every function as first parameter
# You can connect to several databases at once as long as you
# have different conn objects for each one

conn = pys.connect('localhost','root','sql8ouijas4')
print "done"

# event detail.
# With this option you can set how much information do you
# want to retrieve.
#
# eventdetail = 0 : Source IP/Port, Destination IP/PORT, Protocol
#                   Signature Data
# eventdetail = 1 : Idem 0 but with Signature References
# eventdetail = 2 : Idem 1 but with protocol info (But no payload)
# eventdetail = 3 : Everything (Payload Included)
pys.eventdetail=3

print ""
print "SENSORS INFO --------------------------"
print "Total Sensors: " + str(len(pys.getAllSensors(conn)))

# Put in sens an array with all the sensors.
sens = pys.getAllSensors(conn)

for i in range(len(pys.getAllSensors(conn))):
  print "   Sensor ID: " + str(sens[i].sensor_id)
  print "   Sensor Hostname: " + sens[i].hostname
  print "   Sensor Interface: " + sens[i].interface
  print "   Sensor Filter: " + str(sens[i].filter)
  print "   Sensor Encoding: " + pys.getEncodingType(conn, sens[i].encoding)
  print "   Sensor Detail: " + str(sens[i].detail)
  print 
  
print "EVENT STATS ---------------------------"
print "Total Events (getEventCount): " + str(pys.getEventCount(conn))
print "Total Unique Alerts (getUniqueSignatureCount): " + str(pys.getUniqueSignatureCount(conn))
# Get alert in the specified time lapse.
print "Last Week Alerts: (getEventByTimeRange): " + str(len(pys.getEventByTimeRange(conn,lastweek,now)))
# Get alerts in specified range. (From 192.168.0.0 to 192.168.255.0)
print "Events originated from 192.168.*.* (getEventBySrcIPRange): " + str(len(pys.getEventBySrcIPRange(conn,'192.168.0.0','192.168.255.255')))
# Get alerts by port 80 in TCP protocol
print "Events to port 80 (getEventByDstPort): " + str(len(pys.getEventByDstPort(conn,'TCP',80)))
print ""
print "EVENT DETAILS -------------------------"

# Get one instance of an Event object with event_id of 1
event = pys.getEventByID(conn,1)
print "Event ID: " + str(event.event_id)
print "Date: " + pys.tuple2SnortDate(event.timestamp)
print "Source IP: " + event.src_ip
print "Source Port: " + str(event.src_port)
print "Destination IP: " +event.dst_ip
print "Destination Port: " + str(event.dst_port)
print "Protocol: " + event.protocol

# Packet Object inherits specific members for each protocol
if (event.protocol == "TCP"):
  print "    seq: " + str(event.packet.seq) + ", win: " + str(event.packet.win) \
+", ack: " + str(event.packet.ack) + ", urp: " + str(event.packet.urp)
  print "    res: " + str(event.packet.res) + ", flags:" + str(event.packet.flags) \
+", checksum: " + str(event.packet.csum) 
  print "   a little bit of payload: " + event.packet.payload[:20]
elif (event.protocol == "UDP"):
  print "    csum:" + str(event.packet.csum) + ", len: " + str(event.packet.len)
  print "    a little bit of payload: " + event.packet.payload[:20]
elif (event.protocol == "ICMP"):
  print "    type:" + str(event.packet.type) + ", code: " + str(event.packet.code)
  print "    csum:" + str(event.packet.csum)

print "Signature ID: " + str(event.signature.id)
print "Signature Name: " + event.signature.name
print "Signature Priority: " + str(event.signature.priority)
print "Signature Classname: " + event.signature.class_name
print "Signature Rev: " + str(event.signature.rev)
print "Signature SID: " + str(event.signature.sid)

# event.signature.references is an array of reference objects
print "Signature References:" + str(len(event.signature.references))
for i in range(len(event.signature.references)):
  print "    Reference " + str(i)
  ref = pys.reference()
  ref = event.signature.references[i]
  print "    System name: " + ref.system_name
  print "    Tag: " + ref.tag
  



     
