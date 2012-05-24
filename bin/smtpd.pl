#!/usr/bin/perl
require 5.006;
use strict;
use warnings;
use IO::Socket;
use IO::Select;
use Net::Server::Mail::SMTP;
use Net::Server::Mail::ESMTP;
use Net::Server::Mail::ESMTP::SIZE;
#Our MailWall related classes.
use lib "/opt/mailwall/lib";
use MailWallDb;
use MailWallQueue;
use MailWall;
use Proc::DaemonLite qw(:all);
use Data::Dumper;
$Data::Dumper::Sortkeys= 1;


#Define $mailwall grobal to accomodate the function callbacks.
our $mailwall;
#Define all the callback functions so they forward to the MailWall object.
sub validate_peer {
  my($session, $name) = @_;
  $session->{"mailwallsession"} = $mailwall->newsession($session);
  return $session->{"mailwallsession"}->validatePeer($name);
}
sub validate_from {
  my($session, $from) = @_;
  $session->{"mailwallsession"} = $mailwall->newsession($session);
  my ($ok,@attrlist) = $session->{"mailwallsession"}->validatePeer("dummy");
  unless ($ok) { 
     return ($ok,@attrlist);
  }
  return $session->{"mailwallsession"}->validateFrom($from)
}
sub validate_recipient {
  my($session, $recipient) = @_;
  if ($session->{"mailwallsession"}) {
    return $session->{"mailwallsession"}->validateRecipient($recipient);
  } else {
    return(0, 554, "Invalid command sequence");
  }
}
sub queue_message {
  my($session, $data) = @_;
  if ($session->{"mailwallsession"}) {
     return $session->{"mailwallsession"}->queueMessage($data);
  } else {
     return(0, 554, "Invalid command sequence");
  }
}
sub reset_session {
  my ($session) = @_;
  if ($session->{"mailwallsession"}) { 
     return $session->{"mailwallsession"}->resetSession();
  } else {
    return(0, 554, "Invalid command sequence");
  }
}
sub post_quit {
  my ($session) = @_;
  if ($session->{"mailwallsession"}) {
     return $session->{"mailwallsession"}->postQuit();
  }
  return 1;
}
#The main program.

#read the config file.
unless ((open(CONF,"/etc/mailwall.conf")) || (open(CONF,"./mailwall.conf"))) {
  log_warn("ERROR: Unable to open config file\n");
  exit 1;
}
my %CONFIG=();
while(<CONF>) {
  chomp;
  s/\r//g;
  s/\s//g;
  unless (/^\s*#/) {
     my ($key,$val)=split(/=/,$_,2);
     $CONFIG{"$key"}=$val;
  }
}
close(CONF);
my $serverip=$CONFIG{"ip"};
my $spooldir=$CONFIG{"spooldir"};
my $dbfile=$CONFIG{"database"};
my $topdomain=$CONFIG{"topdomain"};
my $user=$CONFIG{"user"};
my $group=$CONFIG{"group"};
my $adminip=$CONFIG{"adminip"};
my $adminuser=$CONFIG{"adminuser"};
my $daemonize=$CONFIG{"daemonize"};
my $basenet=$CONFIG{"basenet"};
my $maxmessagesize = $CONFIG{"maxmessagesize"};
my $oldsmtpmode = $CONFIG{"oldsmtpmode"};
unless (lc($daemonize) eq "true") {
  $daemonize="";
}
my $configok=1;
unless ($serverip) {
  log_warn("ERROR: No 'ip' entry in config file\n");
  $configok=0;
}
unless ($spooldir) {
  log_warn("ERROR: No 'spooldir' entry in config file\n");
  $configok=0;
}
unless ($dbfile) {
  log_warn("ERROR: No 'database' entry in config file\n");
  $configok=0;
}
unless ($topdomain) {
  log_warn("ERROR: No 'topdomain' entry in config file\n");
  $configok=0;
}
unless ($user) {
  log_warn("ERROR: No 'user' entry in config file\n");
  $configok=0;
}
unless ($group) {
  log_warn("ERROR: No 'group' entry in config file\n");
  $configok=0;
}
unless ($basenet) {
  log_warn("ERROR: No 'basenet' entry in config file\n");
  $configok=0;
}
unless ($maxmessagesize) {
   log_warn("ERROR: No 'maxmessagesize' entry in config file\n");
   $configok=0;
}
if (lc($oldsmtpmode) eq "false") {
   $oldsmtpmode=0;  
} else {
  $oldsmtpmode=1;
}
unless ($configok) {
  exit 1;
}


#Bind to port 25, need to run as root for this.
my $servermainsocket = IO::Socket::INET -> new (Listen => 5,
Proto => 'tcp',
LocalPort => 25,
LocalAddr => $serverip,
ReuseAddr => 1
);

unless ($servermainsocket) {
   log_die("Unable to bind to TCP port 25:  $!\n");
   exit 1;
}

umask(63);
if ($daemonize) {
  init_server(undef,$user,$group);
}
#After dropping priviledges create the core objects.
#Create the database object.
my $database=new MailWallDb(dbpath => $dbfile, adminip => $adminip , adminuser => $adminuser, basenet => $basenet);
#$database->BUILD();
#Create the queue object.
unless (-d "$spooldir") {
   mkdir($spooldir);
}
unless (-d "$spooldir") {
   log_die("The spooldir $spooldir does not exist and unable to create it.");
}

my $queue=new MailWallQueue(spoolpath => $spooldir, db => $database, domain=> $topdomain);
#Create the MailWall object.
$mailwall = new MailWall(queue => $queue,db => $database);
#Use IO::Select to process multiple connections at the same time.
my $select = new IO::Select $servermainsocket;
my(@socketswithevents, $socket, %session_pool);
#can_read returns both on new incomming connections on the server socket and on data on connected sockets.
while(@socketswithevents= $select->can_read)
{
   #Process all sockets with activity, including the server socket.
   foreach $socket (@socketswithevents) {
     if($socket == $servermainsocket) {
          #Accept new server connections and bind it to Net::Server::Mail::SMTP,
	  #our SMTP callbacks, and the select session pool.
          my $new = $servermainsocket->accept();
	  my $peer=$new->peerhost();
	  
	  $select->add($new);
	  $new->blocking(0);
	  my $smtp;
          if ($oldsmtpmode) {
	    $smtp = new Net::Server::Mail::SMTP socket => $new
	       or log_die("can't start server on port 25");
          } else {
            $smtp = new Net::Server::Mail::ESMTP socket => $new
               or log_die("can't start server on port 25");
          }
	  $smtp->{"peer"}=$peer;
          unless ($oldsmtpmode) {
	      $smtp->register('Net::Server::Mail::ESMTP::PIPELINING');
	      $smtp->register('Net::Server::Mail::ESMTP::8BITMIME');
              $smtp->register('Net::Server::Mail::ESMTP::SIZE');
              $smtp->set_size($maxmessagesize);
          }
	  $smtp->set_callback(MAIL => \&validate_from);
	  $smtp->set_callback(RCPT => \&validate_recipient);
	  $smtp->set_callback(DATA => \&queue_message);
	  $smtp->set_callback(RSET => \&reset_session);
	  $smtp->set_callback(QUIT => \&post_quit);
          if ($oldsmtpmode) {
              $smtp->{"banner_string"}="mailwall SMTP MailWall-II Service ready";
          } else {
              $smtp->{"banner_string"}="mailwall ESMTP MailWall-II Service ready";
          }
          $smtp->banner();
	  $session_pool{$new} = $smtp;
     } else {
          #Process incomming data on connected sockets.
          my $operation = join '', <$socket>;
          my $rv;
          if ($session_pool{$socket}->{"in"}->connected()) {
             $rv = $session_pool{$socket}->process_once($operation);
             if(defined $rv)
             {
                $select->remove($socket);
                delete $session_pool{$socket};
                $socket->close();
             }
          } else {
               $select->remove($socket);
               delete $session_pool{$socket};
          }
     }
   }
}

