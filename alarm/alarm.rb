require 'packetfu'



stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)



$num_incidents = 1
def report_incident(type, source, protocol, payload)
    payload = payload.each_byte.map { |b| sprintf("0x%02X ",b) }.join
    puts "#{$num_incidents}. ALERT: #{type} is detected from #{source}"
        " (#{protocol}) (#{payload})!\n"
    $num_incidents += 1
end


def is_null_scan?(packet)
    flags = packet.tcp_flags
    flags.select {|flag| flag != 0}.empty?
end

def is_fin_scan?(packet)
    flags = packet.tcp_flags
    flags.select {|flag| flag != 0}.length == 1 and flags.fin != 0
end

def is_xmas_scan?(packet)
    flags = packet.tcp_flags
    flags.select {|flag| flag != 0}.length == 3 and
        flags.fin != 0 and flags.psh != 0 and flags.urg != 0
end

def find_credit_cards_in(packet)
    if packet.payload =~ /4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ or
       packet.payload =~ /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ or
       packet.payload =~ /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ or
       packet.payload =~ /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/
        report_incident("Credit card leak", packet.saddr, "HTTP", packet.payload)
    end
end

stream.stream.each do |raw_data|
    packet = PacketFu::Packet.parse raw_data
    if packet.class == PacketFu::TCPPacket
        if is_null_scan? packet
            report_incident("NULL scan", packet.ip_saddr, "TCP", packet.payload)
        elsif is_fin_scan? packet
            report_incident("FIN scan", packet.ip_saddr, "TCP", packet.payload)
        elsif is_xmas_scan? packet
            report_incident("XMAS scan", packet.ip_saddr, "TCP", packet.payload)
        else
            print packet.payload
        end
        find_credit_cards_in packet
        puts "TCP\n"
    elsif packet.class == PacketFu::IPPacket
        puts "IP\n"
    elsif packet.class == PacketFu::UDPPacket
        puts "UDP\n"
    elsif packet.class == PacketFu::EthPacket
        puts "ETH\n"
    end
end


