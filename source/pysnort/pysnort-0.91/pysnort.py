# pysnort: Snort Library for Python
# version 0.91
# Written by: Ignacio Vazquez <irvazquez@users.sourceforge.net>

# Add Support to other databases

import MySQLdb
import time
from string import upper, find, split

 
class mysqlLog:
  """Mysql log class"""
  
  # Use sensor_id array to specificate which sensors do you want to use
  sensor_id = [1]

  # Event detail defaults to full retrieving
  eventdetail = 3
  class Csignature:
    id = 0
    name = ''
    class_name = ''
    priority = ''
    sid = 0
    rev = 0
    references = []  

  class ipPacket:
      ver = 0
      hlen = 0
      tos = 0
      len = 0
      id = 0
      flags = 0
      off= 0
      ttl= 0
      proto = 0
      csum = 0   
    
  class packet:
    """Base class for packets"""
    protocol = ''
    csum = 0
    ip = None
    
  class udpPacket(packet):
    """UDP Packet class (inherits from 'packet')"""
    len = 0
    payload = ''
    
  class tcpPacket(packet):
    """TCP Packet class (inherits from 'packet')"""
    seq = 0
    ack = 0
    off = 0
    res = 0
    win = 0
    urp = 0
    flags = 0
    payload = ''
    
  class icmpPacket(packet):
    """ICMP Packet class (inherits from 'packet')"""
    type = 0
    code = 0
    id = 0
    
  class sensor:
    """Sensor class"""
    sensor_id = 0
    hostname = ''
    interface = ''
    filter = ''
    detail = 0
    encoding = 0

  class reference:
    """Reference data class"""
    system_name = ''
    tag = ''

  class event:
    """Event details class"""
    event_id = 0
    sensor_id = 0
    protocol = 0
    src_ip = ''
    src_port= 0
    dst_ip = ''
    dst_port = 0
    timestamp = ''
    packet = None
    signature = None
  
  def snortIP2dot(self, iplong):
    """Transforms an unsigned long int representing an IP into a full-dotted address"""
    ip = str((iplong >> 24) & 255) + "."
    ip = ip + str((iplong >> 16) & 255) + "."
    ip = ip + str((iplong >> 8) & 255) + "."
    ip = ip + str(iplong & 255)
    return ip
  
  def dot2SnortIP(self, dotip):
    """Transforms a dotted-address IP into an unsigned long int"""
    dotip = split(dotip,'.')
    ip = 0
    if (len(dotip) != 4):
      return -1
    for i in range(4):
      ip = ip + (int(dotip[i])  * (256 ** (3-i)))
    return ip
  
  def getEncodingType(self, conn, encoding_id):
    """Returns an string with the name of the encoding used"""
    cursor = conn.cursor()
    cursor.execute("SELECT encoding_text FROM encoding WHERE encoding_type=" + str(encoding_id))
    return(cursor.fetchone()[0])
  
  def getQueryString(self):
    """Generates a standard query string using self.sensor_id array"""
    
    q = """SELECT e.cid, e.sid, ih.ip_proto, ih.ip_src, ih.ip_dst,\
 e.timestamp, e.signature, s.sig_name, sc.sig_class_name, sc.sig_class_id, s.sig_id, s.sig_priority, s.sig_rev, s.sig_sid FROM iphdr ih, sig_class sc,\
 event e, signature s WHERE e.signature = s.sig_id AND ih.cid = e.cid AND s.sig_class_id = sc.sig_class_id""" 
    for i in range(len(self.sensor_id)):
      if (i==0):
        q = q + " AND ("
      q = q + "e.sid =" + str(self.sensor_id[i]) + " OR "
      if (i == (len(self.sensor_id) -1)): # is the last one?
        q = q[:-3] + ")"
    return q
  
  def connect(self, host, user, password):
    """Connects with the database and returns a connection object"""
    
    conn = MySQLdb.connect(host, user, password)
    conn.select_db('snort')
    return conn

  def snortDate2Tuple(self, snortdate):
    """Returns snort-formatted date in tuple format""" 
    return time.strptime(snortdate, "%Y-%m-%d %H:%M:%S")
  
  def tuple2SnortDate(self, datetuple):
    """Returns tuple-formatted date in snort format"""
    return time.strftime("%Y-%m-%d %H:%M:%S",datetuple)
  
  def getAllSensors(self, conn):
     """Returns an array with all the working sensors"""
     
     cursor = conn.cursor()
     cursor.execute("""select sid, hostname, interface, filter, detail, \
     encoding from sensor""")
     returnarray = []
     for i in range(cursor.rowcount):
       returndata = self.sensor()
       dbsensor = cursor.fetchone()
       returndata.sensor_id= dbsensor[0]
       returndata.hostname= dbsensor[1]
       returndata.interface= dbsensor[2]
       returndata.filter= dbsensor[3]
       returndata.detail= dbsensor[4]
       returndata.encoding= dbsensor[5]
       returnarray.append(returndata)
       del returndata
     del cursor
     return returnarray
  
  def getProtocolName(self, num):
    """Returns a string with the name of the protocol num"""
    if (num == 1):
      return "ICMP"
    elif (num == 6):
      return "TCP"
    elif (num == 17):
      return "UDP"
    else:
      return -1
    
  def getProtocolID(self, proto):
    """Returns the integer ID of the protocol""" 
    proto = upper(proto)
    if (proto == "ICMP"):
      return 1
    elif (proto == "TCP"):
      return 6
    elif (proto == "UDP"):
      return 17
    else:
      return -1
    
  def buildCustomQuery(self, q):
    """Builds an SQL String with the corresponding sensor ids"""
    if (find(q, 'event e') == -1):
        colname = "event.sid="
    else:
        colname = "e.sid ="
    for i in range(len(self.sensor_id)):
      if (i==0):
        q = q + " AND ("
      q = q + colname + str(self.sensor_id[i]) + " OR "
      if (i == (len(self.sensor_id) -1)): # is the last one?
        q = q[:-3] + ")"
    return q
  
# GOTTA MAKE THIS BETTER!
  def __buildPortCustomQueryTCP(self, q):
    """Internal Function"""
    for i in range(len(self.sensor_id)):
      if (i==0):
        q = q + " AND ("
      q = q + "tcphdr.sid =" + str(self.sensor_id[i]) + " OR "
      if (i == (len(self.sensor_id) -1)): # is the last one?
        q = q[:-4] + ")"
    return q  

  def __buildPortCustomQueryTCP2(self, q):
    """Internal Function"""
    for i in range(len(self.sensor_id)):
      if (i==0):
        q = q + " AND ("
      q = q + "th.sid =" + str(self.sensor_id[i]) + " OR "
      if (i == (len(self.sensor_id) -1)): # is the last one?
        q = q[:-4] + ")"
    return q 
  def __buildPortCustomQueryUDP(self, q):
    """Internal Function"""
    for i in range(len(self.sensor_id)):
      if (i==0):
        q = q + " AND ("
      q = q + "udphdr.sid =" + str(self.sensor_id[i]) + " OR "
      if (i == (len(self.sensor_id) -1)): # is the last one?
        q = q[:-4] + ")"
    return q  

  def __buildPortCustomQueryICMP(self, q):
    """Internal Function"""
    for i in range(len(self.sensor_id)):
      if (i==0):
        q = q + " AND ("
      q = q + "icmphdr.sid =" + str(self.sensor_id[i]) + " OR "
      if (i == (len(self.sensor_id) -1)): # is the last one?
        q = q[:-4] + ")"    
    return q

  def __buildDataCustomQuery(self, q):
    """Internal Function"""
    for i in range(len(self.sensor_id)):
      if (i==0):
        q = q + " AND ("
      q = q + "data.sid =" + str(self.sensor_id[i]) + " OR "
      if (i == (len(self.sensor_id) -1)): # is the last one?
        q = q[:-4] + ")"
    return q


  def __getHostsPorts(self, conn, cid, proto):
    """Internal Function"""
    if (proto == "TCP"):
      query = self.__buildPortCustomQueryTCP("""SELECT tcp_sport, tcp_dport FROM tcphdr WHERE \
              cid = """ + str(cid))
    elif (proto == "UDP"):
      query = self.__buildPortCustomQueryUDP("""SELECT udp_sport, udp_sport FROM udphdr WHERE \
              cid = """ + str(cid))
    elif (proto == "ICMP"):
      return ((0,0))
   
    cursor2 = conn.cursor()
    cursor2.execute(query)
    if (cursor2.rowcount != 1):
      return ((-1,-1))
    
    dbevent2 = cursor2.fetchone()
    del cursor2
    return ((dbevent2[0], dbevent2[1]))

  def executeQuery(self, conn, query_clause):
    """Executes a query and returns the error code"""
    cursor = conn.cursor()
    return (cursor.execute(query_clause))
  
  def executeRSQuery(self, conn, query_clause):
    """Executes a query and returns an array with the data"""
    cursor = conn.cursor()
    cursor.execute(query_clause)
    return (cursor.fetchall())
  
  def getSigClassName(self, conn, class_id):
    """Gets a class Name (sig_class_name) for a class ID (sig_class_id)"""
    
    query = """SELECT sig_class_name FROM sig_class WHERE sig_class_id="""+str(class_id)
    cursor = conn.cursor()
    cursor.execute(query)
    if (cursor.rowcount > 0):
      return cursor.fetchone()[0]
    else:
      return -1
    
  def getSigClassID(self, conn, sig_class_name):
    """Returns the Class_ID for 'sig_class_name'"""
    
    query = """SELECT sig_class_name FROM sig_class WHERE sig_class_name="""+str(sig_class_name)
    cursor = conn.cursor()
    cursor.execute(query)
    if (cursor.rowcount > 0):
      return cursor.fetchone()[0]
    else:
      return -1  
    
  def fillSignatureData(self, conn, rs):
    """Returns a CSignature object from the given recordset"""
    sigdata = self.Csignature()
    sigdata.references = []
    sigdata.id = rs[0]
    sigdata.name = rs[1]
    sigdata.class_name = self.getSigClassName(conn,rs[2])
    sigdata.priority = rs[3]
    sigdata.rev = rs[4]
    sigdata.sid = rs[5]
    query = "SELECT rs.ref_system_name, r.ref_tag FROM reference r, reference_system rs, sig_reference sr WHERE r.ref_system_id = rs.ref_system_id AND sr.ref_id = r.ref_id AND sr.sig_id=" + str(rs[0])  
    cursor3 = conn.cursor()
    cursor3.execute(query)
    for i in range(cursor3.rowcount):
      refdata = self.reference()
      x = cursor3.fetchone()
      refdata.system_name = x[0]
      refdata.tag = x[1]
      sigdata.references.append(refdata)      
      del refdata
    del cursor3
    return sigdata
  
  def fillLightSignatureData(self, conn, rs):
    """Returns a CSignature object from the given recordset but without the reference data"""
    sigdata = self.Csignature()
    sigdata.references = []
    sigdata.id = rs[0]
    sigdata.name = rs[1]
    sigdata.class_name = self.getSigClassName(conn,rs[2])
    sigdata.priority = rs[3]
    sigdata.rev = rs[4]
    sigdata.sid = rs[5]
    return sigdata
  
  def getAllSignatures(self, conn):
    """Returns an array with all the signatures found"""
    cursor = conn.cursor()
    query = """SELECT sig_id, sig_name, sig_class_id, sig_priority, sig_rev, sig_sid FROM signature"""
    cursor.execute(query)
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillSignatureData(conn,cursor.fetchone()))
    del cursor
    return(returnarray) 
  
  def getSignatureByID(self, conn, sig_id):
    """Returns a CSignature object given the corresponding sig_id"""
    
    cursor = conn.cursor()
    query = """SELECT sig_id, sig_name, sig_class_id, sig_priority, sig_rev, sig_sid FROM signature WHERE sig_id="""+str(sig_id)
    if(cursor.execute(query) == 0):
       return -1
    return(self.fillSignatureData(conn,cursor.fetchone()))     
  
  def getSignatureByName(self, conn, sig_name):
    """Returns a CSignature object given the corresponding sig_name"""
    
    cursor = conn.cursor()
    query = """SELECT sig_id, sig_name, sig_class_id, sig_priority, sig_rev, sig_sid FROM signature WHERE sig_name='""" + str(sig_name) + """'"""
    if(cursor.execute(query) == 0):
       return -1
    return(self.fillSignatureData(conn,cursor.fetchone()))

  def getSignatureByPriority(self, conn, sig_priority):
    """Returns a CSignature object array given for the given sig_priority"""
    
    cursor=conn.cursor()
    cursor.execute(query)
    query = """SELECT sig_id, sig_name, sig_class_id, sig_priority, sig_rev, sig_sid FROM signature WHERE sig_priority=""" + str(sig_priority)
    resultarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillSignatureData(conn,cursor.fetchone()))
    del cursor
    return returnarray
  
  def getSignatureBySID(self,conn,sig_sid):
    """Returns a CSignature object given the corresponding sig_sid"""
    
    cursor=conn.cursor()
    cursor.execute(query)
    query = """SELECT sig_id, sig_name, sig_class_id, sig_priority, sig_rev, sig_sid FROM signature WHERE sig_sid=""" + str(sig_sid)
    returnarray = []
    if(cursor.execute(query) == 0):
       return -1
    return(self.fillSignatureData(conn,cursor.fetchone())) 
  
  def getSignatureByRev(self,conn,sig_rev):
    """Returns a CSignature object given the corresponding sig_rev"""
    cursor=conn.cursor()
    cursor.execute(query)
    query = """SELECT sig_id, sig_name, sig_class_id, sig_priority, sig_rev, sig_sid FROM signature WHERE sig_rev=""" + str(sig_rev)
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillSignatureData(conn,cursor.fetchone()))
    del cursor
    return returnarray  
  
  def getSignatureByClassName(self,conn,sig_class):
    """Returns a CSignature object array given the class name"""
    cursor=conn.cursor()
    cursor.execute(query)
    query = """SELECT sig_id, sig_name, sig_class_id, sig_priority, sig_rev, sig_sid FROM signature WHERE sig_class_id=""" + self.getSigClassID(sig_class)
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillSignatureData(conn,cursor.fetchone()))
    del cursor
    return returnarray     
  
  def getSignatureByClassID(self,conn,sig_class_id):
    """Returns a CSignature object array given the class id"""
    cursor=conn.cursor()
    cursor.execute(query)
    query = """SELECT sig_id, sig_name, sig_class_id, sig_priority, sig_rev, sig_sid FROM signature WHERE sig_class_id=""" + str(sig_class_id)
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillSignatureData(conn,cursor.fetchone()))
    del cursor
    return returnarray      

  def getPacketPayload(self, conn, event_id):
    """Returns the data payload from packet event_id"""
    
    query = """SELECT data_payload FROM data where cid=""" + str(event_id) 
    cursor = conn.cursor()
    cursor.execute(self.__buildDataCustomQuery(query))
    if (cursor.rowcount != 1):
      return('')
    else:
      return (cursor.fetchone()[0])
    
  def getEventCount(self,conn):
    """Returns an integer with the number of events occured"""
    query = "SELECT count(*) from event WHERE 0=0"
    cursor = conn.cursor()
    cursor.execute(self.buildCustomQuery(query))
    return (cursor.fetchone()[0])
  
  def getUniqueSignatureCount(self, conn):
    """Returns an integer with the number of unique signatures found"""
    query = "SELECT DISTINCT signature from event WHERE 0=0"
    cursor = conn.cursor()
    cursor.execute(self.buildCustomQuery(query))
    return (cursor.rowcount)
  
  def getUniqueSignaturesID(self, conn):
    """Returns an array of integers with the signature_id of the unique signatures"""
    query = "SELECT DISTINCT signature from event WHERE 0=0"
    cursor = conn.cursor()
    cursor.execute(self.buildCustomQuery(query))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.getSignatureByID(conn, cursor.fetchone()[0]))
    del cursor
    return returnarray

  def getProtocolData(self, conn, proto, event_id, sensor_id):
    """Fills protocol specific data for event_id and ensor_id"""

    if (upper(proto) == 'TCP'):
      cursor=conn.cursor()
      query = "SELECT th.tcp_seq, th.tcp_ack, th.tcp_off, th.tcp_res, th.tcp_flags, th.tcp_win, th.tcp_csum, th.tcp_urp,\
 ih.ip_ver, ih.ip_hlen, ih.ip_tos, ih.ip_len, ih.ip_id, ih.ip_flags, ih.ip_off, ih.ip_ttl, ih.ip_proto, ih.ip_csum \
  FROM tcphdr th, iphdr ih WHERE th.cid = ih.cid AND th.sid = ih.sid AND th.cid=" + str(event_id) + " AND th.sid=" + str(sensor_id)
      cursor.execute(self.__buildPortCustomQueryTCP2(query))
      if (cursor.rowcount != 1):
        return -1
      else:
        rs = cursor.fetchone()
        returndata = self.tcpPacket()
        returndata.protocol=upper(proto)
        returndata.seq = rs[0]
        returndata.ack = rs[1]
        returndata.off = rs[2]
        returndata.res = rs[3]
        returndata.flags = rs[4]
        returndata.win = rs[5]
        returndata.csum = rs[6]
        returndata.urp = rs[7]
        returndata.ip = self.ipPacket()
        returndata.ip.ver = rs[8]
        returndata.ip.hlen = rs[9]
        returndata.ip.tos = rs[10]
        returndata.ip.len = rs[11]
        returndata.ip.id=rs[12]
        returndata.ip.flags=rs[13]
        returndata.ip.off=rs[14]
        returndata.ip.ttl=rs[15]
        returndata.ip.proto=rs[16]
        returndata.ip.csum=rs[17]
        if (self.eventdetail == 3):
          returndata.payload = self.getPacketPayload(conn, event_id)
        del cursor
        del rs
        return returndata
      
    elif (upper(proto) == 'UDP'):
      cursor=conn.cursor()  
      query = "SELECT udphdr.udp_len, udphdr.udp_csum, \
ih.ip_ver, ih.ip_hlen, ih.ip_tos, ih.ip_len, ih.ip_id, ih.ip_flags, ih.ip_off, ih.ip_ttl, ih.ip_proto, ih.ip_csum \
FROM udphdr, iphdr ih WHERE udphdr.cid = ih.cid AND udphdr.sid = ih.sid AND udphdr.cid="+str(event_id) 
      
      cursor.execute(self.__buildPortCustomQueryUDP(query))
      if (cursor.rowcount != 1):
        return -1
      else:
        rs = cursor.fetchone()
        returndata = self.udpPacket()
        returndata.protocol = upper(proto)
        returndata.len = rs[0]
        returndata.csum = rs[1]
        returndata.ip = self.ipPacket()
        returndata.ip.ver = rs[2]
        returndata.ip.hlen = rs[3]
        returndata.ip.tos = rs[4]
        returndata.ip.len = rs[5]
        returndata.ip.id=rs[6]
        returndata.ip.flags=rs[7]
        returndata.ip.off=rs[8]
        returndata.ip.ttl=rs[9]
        returndata.ip.proto=rs[10]
        returndata.ip.csum=rs[11]
        returndata.payload = self.getPacketPayload(conn, event_id) 
        return returndata
      
    elif (upper(proto) == 'ICMP'):
      cursor=conn.cursor()
      query = "SELECT icmphdr.icmp_type, icmphdr.icmp_code, icmphdr.icmp_csum, icmphdr.icmp_id, icmphdr.icmp_seq, ih.ip_ver, ih.ip_hlen, ih.ip_tos, ih.ip_len, ih.ip_id, ih.ip_flags, ih.ip_off, ih.ip_ttl, ih.ip_proto, ih.ip_csum FROM icmphdr, iphdr ih WHERE icmphdr.sid = ih.sid AND icmphdr.cid = ih.cid AND icmphdr.cid=" + str(event_id)
      cursor.execute(self.__buildPortCustomQueryICMP(query))
      if (cursor.rowcount != 1):
        return -1
      else:
        rs = cursor.fetchone()
        returndata = self.icmpPacket()
        returndata.protocol = upper(proto)
        returndata.type = rs[0]
        returndata.code = rs[1]
        returndata.csum = rs[2]
        returndata.id = rs[3]
        returndata.seq = rs[4]
        returndata.ip = self.ipPacket()
        returndata.ip.ver = rs[5]
        returndata.ip.hlen = rs[6]
        returndata.ip.tos = rs[7]
        returndata.ip.len = rs[8]
        returndata.ip.id=rs[9]
        returndata.ip.flags=rs[10]
        returndata.ip.off=rs[11]
        returndata.ip.ttl=rs[12]
        returndata.ip.proto=rs[13]
        returndata.ip.csum=rs[14]
        return returndata
    else:
      return -1

  def fillEventData(self, conn, rs):
    """Fills the Event class with the cursor rs"""
    returnevent = self.event()
    returnevent.event_id = rs[0]
    returnevent.sensor_id = rs[1]
    returnevent.protocol = self.getProtocolName(rs[2])
    returnevent.src_ip = self.snortIP2dot(rs[3])
    returnevent.dst_ip = self.snortIP2dot(rs[4])
    returnevent.timestamp = self.snortDate2Tuple(rs[5])
    portsdata = []
    portsdata = self.__getHostsPorts(conn, returnevent.event_id, returnevent.protocol)
    returnevent.src_port = portsdata[0]
    returnevent.dst_port = portsdata[1]

    if (self.eventdetail >= 1):
      returnevent.signature = self.fillSignatureData(conn, (rs[10], rs[7], rs[9], rs[11], rs[12], rs[13]))
    else:
      returnevent.signature = self.fillLightSignatureData(conn, (rs[10], rs[7], rs[9], rs[11], rs[12], rs[13]))
      
    if (self.eventdetail >= 2):      
      returnevent.packet = self.getProtocolData(conn, returnevent.protocol, rs[0],rs[1])
    return returnevent

  def getAllEvents(self, conn):
    """Returns an array with all the events in the database"""
    cursor = conn.cursor()
    cursor.execute(self.getQueryString())
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray
  
  def getLastEvents(self, conn, number):
    """Returns an array with the last 'number' events"""
    cursor = conn.cursor()
    cursor.execute(self.getQueryString() + " ORDER BY timestamp LIMIT " + str(number))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray
  
  def getEventByID(self, conn, event_id):
    """Returns an event object with the specified event_id"""
    cursor = conn.cursor()
    if(cursor.execute(self.getQueryString() +" AND e.cid="+str(event_id)) != 1):
      pass
    return (self.fillEventData(conn,cursor.fetchone()))
  
  def getEventByIDRange(self, conn, event_id_first, event_id_last):
    """Returns an array with all events between event_id_first and event_id_last. Use 0 as wildcard"""
    cursor = conn.cursor()
    if (event_id_first == 0 and event_id_last == 0):
      cursor.execute(self.getQueryString())
    elif (event_id_first == 0):
      cursor.execute(self.getQueryString() + " AND e.cid <= " + str(event_id_last))
    elif (event_id_last == 0):
      cursor.execute(self.getQueryString() + " AND e.cid >= " + str(event_id_first))   
    else:
      cursor.execute(self.getQueryString() + " AND e.cid >=" + str(event_id_first) + " AND e.cid <= " + str(event_id_last))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray
  
  def getEventBySignatureID(self, conn, signature_id):
    """Returns an array of event objects that match the signature ID"""
    cursor = conn.cursor()
    if(cursor.execute(self.getQueryString() + " AND e.signature = " + str(signature_id)) != 1):
      return -1
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray

  def getEventBySrcPort(self, conn, proto, port):
    """Returns an array of event objects that match the Source Port"""
    cursor = conn.cursor()
    if (proto == "TCP"):
      event_port_query = """SELECT event.cid FROM event, tcphdr WHERE tcphdr.cid=event.cid AND tcphdr.tcp_sport=""" + str(port)
      cursor.execute(self.__buildPortCustomQueryTCP(event_port_query))
    elif (proto == "UDP"):
      event_port_query = """SELECT event.cid FROM event, udphdr WHERE udphdr.cid=event.cid AND udphdr.udp_sport=""" + str(port)
      cursor.execute(self.__buildPortCustomQueryUDP(event_port_query))
    else:
      return -1
    returnarray=[]
    for i in range(cursor.rowcount):
      returnarray.append(self.getEventByID(conn, cursor.fetchone()[0]))
    del cursor
    return returnarray
  
  def getEventByDstPort(self, conn, proto, port):
    """Returns an array of event objects that match the Destination Port"""
    cursor = conn.cursor()
    if (proto == "TCP"):
      event_port_query = """SELECT event.cid FROM event, tcphdr WHERE tcphdr.cid=event.cid AND tcphdr.tcp_dport=""" + str(port)
      cursor.execute(self.__buildPortCustomQueryTCP(event_port_query))
    elif (proto == "UDP"):
      event_port_query = """SELECT event.cid FROM event, udphdr WHERE udphdr.cid=event.cid AND udphdr.udp_dport=""" + str(port)
      cursor.execute(self.__buildPortCustomQueryUDP(event_port_query))
    else:
      return -1
    returnarray=[]
    for i in range(cursor.rowcount):
      returnarray.append(self.getEventByID(conn, cursor.fetchone()[0]))
    del cursor
    return returnarray
  
  def getEventBySensorID(self, conn, sensor_id):
    """Returns an array of event objects that match the Sensor ID"""
    cursor = conn.cursor()
    cursor.execute(self.getQueryString() + " AND e.sid = " + str(sensor_id))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray
  
  def getEventByProtocol(self, conn, proto):
    """Returns an array of event objects that match the Protocol"""
    cursor = conn.cursor()
    cursor.execute(self.getQueryString() + " AND ih.ip_proto = " + str(self.getProtocolID(proto)))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray

  def getEventBySrcIP(self, conn, ip):
    """Returns an array of event objects that match the Source IP"""
    cursor = conn.cursor()
    cursor.execute(self.getQueryString() + " AND ih.ip_src=" + str(self.dot2SnortIP(ip)))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray                 
  
  def getEventBySrcIPRange(self, conn, start_ip, end_ip):
    """Returns and array of event objects that has any of the source addresses between start_ip and end_ip"""
    cursor = conn.cursor()
    cursor.execute(self.getQueryString() + " AND ih.ip_src >= " +str(self.dot2SnortIP(start_ip)) + " AND ih.ip_src <= " + str(self.dot2SnortIP(end_ip)))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray
  
  def getEventByDstIP(self, conn, ip):
    """Returns an array of event objects that match the Destination IP"""
    cursor = conn.cursor()
    cursor.execute(self.getQueryString() + " AND ih.ip_dst=" + str(self.dot2SnortIP(ip)))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray

  def getEventByDstIPRange(self, conn, start_ip, end_ip):
    """Returns and array of event objects that has any of the destination addresses between start_ip and end_ip"""
    
    cursor = conn.cursor()
    cursor.execute(self.getQueryString() + " AND ih.ip_dst >= " +str(self.dot2SnortIP(start_ip)) + " AND ih.ip_dst <= " + str(self.dot2SnortIP(end_ip)))
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray
  

  def getEventByTimestamp(self, conn, timestamp):
    """Returns and array of event objects that happened exactly at the timestamp date"""
    
    cursor = conn.cursor()
    cursor.execute(self.getQueryString() + " AND e.timestamp='" + self.tuple2SnortDate(timestamp) + "'")
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray
  
  def getEventByTimeRange(self, conn, ts_from, ts_to):
    """Returns and array of event objects that happened between ts_from and ts_to. Use 0 as wildcard"""
    
    cursor = conn.cursor()
    if (ts_to == 0 and ts_from == 0):
      tsquery = self.getQueryString()
    elif (ts_from == 0):
      tsquery = self.getQueryString() + " AND e.timestamp <= '"+self.tuple2SnortDate(ts_to)+"'"
    elif (ts_to == 0):
      tsquery = self.getQueryString() + " AND e.timestamp >= '"+self.tuple2SnortDate(ts_from)+"'"
    else:
      tsquery = self.getQueryString() + " AND e.timestamp >= '"+self.tuple2SnortDate(ts_from) + "' AND e.timestamp <= '" + self.tuple2SnortDate(ts_to) + "'"
    cursor.execute(tsquery)
    returnarray = []
    for i in range(cursor.rowcount):
      returnarray.append(self.fillEventData(conn, cursor.fetchone()))
    del cursor
    return returnarray