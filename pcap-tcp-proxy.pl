#!/usr/bin/perl

use strict;
use warnings;
use IO::Select;
use IO::Socket;
use Net::PcapWriter;


my $pcap = shift @ARGV;
my $listen_port = shift @ARGV;
my $target_host = shift @ARGV;
my $target_port = shift @ARGV;
my $verbose = shift @ARGV || 0;

die "Usage: $0 (path-to-dest.pcap|-) listen_port target_host target_port [verbose]
Eg. $0 /tmp/mysession 444 127.0.0.1 443 1
" if(!$target_port);
$| = 1;
Net::PcapWriter::IP->calculate_checksums(0);

my %accepted_to_target;
my %target_to_accepted;
my %accepted_str_helper;
my %accepted_to_conn;
my %target_to_conn;

my $target_str = "$target_host:$target_port";

my $target_ip = inet_ntoa(inet_aton($target_host));

my $conn_counter = 0;

my $writer;
if($pcap ne "-") {
  $writer = Net::PcapWriter->new($pcap);
  $writer->{fh}->autoflush(1);
} else {
  $verbose = 1;
}

my $lsn = IO::Socket::INET->new(Listen => 1, LocalPort => $listen_port, Reuse => 1);
my $sel = IO::Select->new( $lsn );
while(my @ready = $sel->can_read) {
	for my $fh (@ready) {
    	if($fh == $lsn) {
			my $accepted = $lsn->accept;
			$sel->add($accepted);
			$accepted->autoflush(1);
			
			my $accepted_address = $accepted->peerhost();
			my $accepted_port = $accepted->peerport();
			
			my $accepted_str = "$accepted_address:$accepted_port";
	
			mylog("Incoming connection accepted from $accepted_str; establishing new connection to $target_str");
			
			my $target = IO::Socket::INET->new(PeerAddr => $target_host,
                                 PeerPort => $target_port,
                                 Proto    => 'tcp');
			if($target) {
			   $target->autoflush(1);
  			   $accepted_to_target{$accepted} = $target;
			   $target_to_accepted{$target} = $accepted;
   			   $accepted_str_helper{$accepted} = $accepted_str;
			   mylog("New connection to target $target_str established.");
			   $sel->add($target);
			   
			   $conn_counter++;
			   my $now = time();
			   
			   #my $dest_file = sprintf("%s-%04d-%d-%s-%d-%s-%d.pcap", $dest_prefix, $conn_counter, $now, $accepted_address, $accepted_port, $target_host, $target_port);
			   #mylog("Saving session to: $dest_file");
			   if($writer) {
				   my $conn = $writer->tcp_conn($accepted_address,$accepted_port,$target_ip,$target_port);
				   $accepted_to_conn{$accepted} = $conn;
				   $target_to_conn{$target} = $conn;
			   }
			   
			} else {
			   mylog("Unable to establish connection to target ($target_host:$target_port): $@");
			   do_close($accepted);
			}
			
		}
		elsif($accepted_to_target{$fh}) {
		    # event from the accepted socket
			my $accepted = $fh;
			my $target = $accepted_to_target{$fh};
			
			relay($accepted, $target);
		}
		elsif($target_to_accepted{$fh}) {
		    # event from the target service
			my $target = $fh;
			my $accepted = $target_to_accepted{$fh};
			
			relay($target, $accepted);
		}
		else {
		    mylog("Unknown socket event. Bug?");
		}
	}
}

sub relay {
   my $incoming = shift;
   my $destination = shift;

   my $incoming_str = $accepted_str_helper{$incoming} || $target_str;
   my $destination_str = $accepted_str_helper{$destination} || $target_str;

   eval {
	   my $data = "";
	   my $rc = $incoming->recv($data, 1024);
	   if(!defined($rc)) {
		  die("$incoming_str: Socket error ($!)");
	   }
	   if(!length($data)) {
		  mylog("");
		  die("$incoming_str: Socket EOF");
	   }

	   # we have got some data to be relayed.
	   my $hd = hexdump($data);
	   my $length = length($data);
	   my $inspection_str = "<< $incoming_str >> $target_str ($length bytes)";
	   $inspection_str.= ":\n$hd" if($verbose);
	   
	   mylog($inspection_str);
	   
	   if($accepted_to_conn{$incoming}) {
  	     my $conn = $accepted_to_conn{$incoming};
		 $conn->write(0, $data);
	   } 
	   elsif($target_to_conn{$incoming}){
  	     my $conn = $target_to_conn{$incoming};
		 $conn->write(1, $data);
	   }
	   # else simple stderr based inspection is wanted


	   $rc = $destination->send($data);
	   if(!$rc) {
		  die("$target_str: send failed, aborting.");
	   }
	   # mylog("send returned: $rc");
   
   };

   if($@) {   
      mylog("!! $@");
      # need to close both sockets
	  do_close($incoming);
	  do_close($destination);
	  return;
   }

}

sub do_close {
   my $sock = shift;
   my $str = get_str($sock);
   $sel->remove($sock);
   $sock->close;
   delete $accepted_str_helper{$sock};
   delete $accepted_to_target{$sock};
   delete $target_to_accepted{$sock};

   my $conn = $target_to_conn{$sock};
   undef $conn if($conn);
   delete $target_to_conn{$sock};
   
   $conn = $accepted_to_conn{$sock};
   undef $conn if($conn);
   delete $accepted_to_conn{$sock};
   
   mylog("!! $str: closed.");
}

sub get_str {
   my $sock = shift;
   return $accepted_str_helper{$sock} || $target_str;
}

sub mylog {
   my $msg = shift;
   my $now = localtime;
   print STDERR "[$now] $msg\n";
}

sub hexdump($)
{
    my $offset = 0;
	my $re = "";
        
    foreach my $chunk (unpack "(a16)*", $_[0])
    {
        my $hex = unpack "H*", $chunk; # hexadecimal magic
        $chunk =~ tr/ -~/./c;          # replace unprintables
        $hex   =~ s/(.{1,8})/$1 /gs;   # insert spaces
        $re.= sprintf "0x%08x (%05u)  %-*s %s\n",
            $offset, $offset, 36, $hex, $chunk;
        $offset += 16;
    }
	return $re;
}
