#!/usr/bin/perl

use strict;
use warnings;
use IO::Select;
use IO::Socket;
use Net::PcapWriter;
use HTTP::Request;
use IO::Socket::SSL;
 
my $pcap = shift @ARGV;
my $listen_port = shift @ARGV;
my $key_and_cert_pem_path = shift @ARGV;
my $session_dir = shift @ARGV || 0;

my $verbose = $ENV{VERBOSE} ? 1 : 0;

die "Usage: $0 (path-to-dest.pcap|-) listen_port path-to-key-and-cert.pem [session_dir]
Eg. $0 /tmp/mysession.pcap 8080 key-and-cert.pem
If session_dir is specified and it is a directory, then plain text files will be written there with the dewrapped content.
If VERBOSE env var is present, hexdump will be displayed on the stderr.
" if(!$key_and_cert_pem_path);
$| = 1;
Net::PcapWriter::IP->calculate_checksums(0);

my %accepted_to_target;
my %target_to_accepted;
my %str_helper;
my %accepted_to_conn;
my %target_to_conn;
my %session_names;
my $conn_counter = 0;

my $writer;
if($pcap ne "-") {
  $writer = Net::PcapWriter->new($pcap);
  $writer->{fh}->autoflush(1);
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
			
			$str_helper{$accepted} = $accepted_str;
	
			mylog("Incoming connection accepted from $accepted_str");
			
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
		elsif(my $incoming_str = $str_helper{$fh}) {
			# this is a socket we just recently accepted and now it fired. Probably the CONNECT message just arrived.
	        my $rc = sysread($fh, my $data, 1024);
 		    if(!defined($rc)) {
			  mylog("$incoming_str: Socket error ($!)");
			  next;
		    }
		    if(!length($data)) {
			  mylog("$incoming_str: Socket EOF");
			  next;
		    }
			
			my $request = HTTP::Request->parse($data);
			# now we need to establish the TCP connection to the remote
			# print $request->as_string;
			
			if($request->method ne "CONNECT") {
				mylog("We support only the CONNECT verb. Client sent: ".$request->method);
				do_close($fh);
			}
			my $target_str = $request->uri;
			mylog("Client requests connecting to $target_str");
			my $target = IO::Socket::INET->new(PeerAddr => $target_str,
                                 Proto    => 'tcp');
			if(!$target) {
			   mylog("Unable to establish TCP connection to target ($target_str): $@");
			   do_close($fh);				
			   next;
			}

		    mylog("New connection to target $target_str established.");
			if(!syswrite($fh, "HTTP/1.0 200 OK\r\n\r\n")) {
				mylog("Unable to respond to the CONNECT message");
				do_close($fh);
				next;
			}
			
			my ($accepted_ip, $accepted_port) = get_ip_and_port($incoming_str);
			my ($target_host, $target_port) = get_ip_and_port($target_str);
			my $target_ip = inet_ntoa(inet_aton($target_host));

			mylog("Trying to upgrade the upstream to TLS...");
			if(!IO::Socket::SSL->start_SSL($target, SSL_verify_mode => SSL_VERIFY_NONE, SSL_hostname => $target_host)) {
				mylog("TLS upgrade to upstream $target_str failed: $SSL_ERROR");
				do_close($fh);
				next;
			}

			delete $str_helper{$fh};
			$sel->remove($fh);
		    mylog("TLS with target $target_str established. Trying to upgrade client to TLS...");
		    if(!IO::Socket::SSL->start_SSL($fh,
				SSL_server => 1,
				SSL_cert_file => $key_and_cert_pem_path,
				SSL_key_file => $key_and_cert_pem_path,
			)) {
				 mylog("TLS upgrade of client $incoming_str failed: $SSL_ERROR");
				 do_close($fh);
				 next;
			}
			
			# this is needed as fh is silently replaced to something else
			$str_helper{$fh} = $incoming_str;
			$sel->add($fh);
			$fh->autoflush(1);
			
			mylog("TLS rewrapping succeeded with both parties.");
			
		    $sel->add($target);
		    $target->autoflush(1);
		    $accepted_to_target{$fh} = $target;
		    $target_to_accepted{$target} = $fh;
		    $str_helper{$target} = $target_str;
			
			my $session_name = sprintf("%03d--%s--%s.bin",$conn_counter, $incoming_str, $target_str);
			$session_name =~ s/:/-/g;
			$session_names{$fh} = $session_name;
			$session_names{$target} = $session_name;
		   
		    $conn_counter++;
		    my $now = time();
			
			
		   
		    #my $dest_file = sprintf("%s-%04d-%d-%s-%d-%s-%d.pcap", $dest_prefix, $conn_counter, $now, $accepted_address, $accepted_port, $target_host, $target_port);
		    #mylog("Saving session to: $dest_file");
		    if($writer) {
			   my $conn = $writer->tcp_conn($accepted_ip,$accepted_port,$target_ip,$target_port);
			   $accepted_to_conn{$fh} = $conn;
			   $target_to_conn{$target} = $conn;
 		    }
			   
		}
		else {
		    mylog("Unknown socket event. Bug?");
		}
	}
}

sub get_ip_and_port {
	my $str = shift;
	die "Unable to parse $str to IP and port" if($str !~ /(.+):(\d+)/);
	return ($1, $2);
}

sub relay {
   my $incoming = shift;
   my $destination = shift;

   my $incoming_str = $str_helper{$incoming};
   my $destination_str = $str_helper{$destination};

   eval {
	   my $session_name = $session_names{$incoming};
	   my $verbose_fh;
	   if(($session_dir)and($session_name)) {
		   open($verbose_fh, ">>$session_dir/$session_name");
	   }

	   my $data = "";
	   my $rc = sysread($incoming, $data, 32768);
	   if(!defined($rc)) {
		  die("$incoming_str: Socket error ($!)");
	   }
	   if(!length($data)) {
		  mylog("");
		  die("$incoming_str: Socket EOF");
	   }

	   if($verbose_fh) {
		   print $verbose_fh $data;
		   close($verbose_fh);
	   }
	   
	   # we have got some data to be relayed.
	   my $hd = hexdump($data);
	   my $length = length($data);
	   my $inspection_str = "<<$incoming_str  >>$destination_str ($length bytes)";
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


	   $rc = syswrite($destination, $data);
	   if(!$rc) {
		  die("$destination_str: send failed, aborting.");
	   }
	   if($rc != length($data)) {
		   warn("We were unable to write the whole data we wanted");
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
   my $str = $str_helper{$sock};
   $sel->remove($sock);
   $sock->close;
   delete $str_helper{$sock};
   delete $accepted_to_target{$sock};
   delete $target_to_accepted{$sock};

   my $conn = $target_to_conn{$sock};
   undef $conn if($conn);
   delete $target_to_conn{$sock};
   
   $conn = $accepted_to_conn{$sock};
   undef $conn if($conn);
   delete $accepted_to_conn{$sock};
   
   delete $session_names{$sock};
   
   mylog("!! $str: closed.");
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
