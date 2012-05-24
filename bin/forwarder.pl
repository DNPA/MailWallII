#!/usr/bin/perl
use Net::SMTP;
use DBI;
use Proc::DaemonLite qw(:all);
use strict;
my %CONFIG=();

unless ((open(CONF,"/etc/mailwall.conf"))||(open(CONF,"./mailwall.conf"))) {
    log_die("No /etc/mailwall.conf or ./mailwall.conf found\n");
    exit 1;
}
while(<CONF>) {
   chomp;
   s/\r//g;
   s/\s+//g;
   unless (/^\s*#/) {
     my ($key,$val)=split(/=/,$_,2);
     $CONFIG{"$key"}=$val;
   }
}
close(CONF);
my $mailwalldbfile=$CONFIG{"database"};
my $topdomain=$CONFIG{"topdomain"};
my $smarthost=$CONFIG{"smarthost"};
my $mailwalluser=$CONFIG{"user"};
my $mailwallgroup=$CONFIG{"group"};
my $daemonize=$CONFIG{"daemonize"};
my $spooldir=$CONFIG{"spooldir"};
unless (lc($daemonize) eq "true") {
  $daemonize="";
}
my $ok=1;
unless ($mailwalldbfile) {
   log_warn("ERROR: No 'database' entry in config file.\n");
   $ok=0;
}
unless ($topdomain) {
   log_warn("ERROR: No 'topdomain' entry in config file.\n");
   $ok=0;
}
unless ($smarthost) {
   log_warn("ERROR: No 'smarthost' entry in config file.\n");
   $ok=0;
}
unless ($mailwalluser) {
   log_warn("ERROR: No 'user' entry in config file.\n");
   $ok=0;
}
unless ($mailwallgroup) {
   log_warn("ERROR: No 'group' entry in config file.\n");
   $ok=0;
}
unless ($spooldir) {
   log_warn("ERROR: No 'spooldir' entry in config file.\n");
   $ok=0;
}
unless ($ok) {
   exit 1;
}
if ($daemonize) {
  init_server(undef,$mailwalluser,$mailwallgroup);
  open(STDOUT,"/dev/null");
  open(STDERR,"/dev/null");
}
my $dbh=DBI->connect("dbi:SQLite:dbname=$mailwalldbfile","","",{ RaiseError => 1, AutoCommit => 1 }) || log_die("Problem with sqlite db at $mailwalldbfile");
#Upscale timeouts on database locks so we should avoid them as much as possible, hope this is sufficient.
my $timeout=$dbh->func( 'busy_timeout' );
$timeout *= 10;
$dbh->func($timeout, 'busy_timeout' );
#Define prepared statements we will be using later on.
my $ps1=$dbh->prepare("select recipient,fspath,person_id from messagequeue where queuename='forward'");
my $ps2=$dbh->prepare("delete from messagequeue where recipient=? AND fspath=?");
my $ps3=$dbh->prepare("UPDATE messagequeue SET queuename='forward' where queuename='delay' and creationtime < ?");
my $ps4=$dbh->prepare("DELETE from messagequeue where creationtime < ?");
my $ps5=$dbh->prepare("DELETE from eventlog where eventtime < ?");
my $ps6=$dbh->prepare("DELETE from peer where confirmed='false' AND creationtime < ?");
my $ps7=$dbh->prepare("VACUUM");
#We want to delete old stuff in 8 days.
my $longwk = 8 * 24 * 60 * 60;
my $lasttime=0;
my $lastbigtime=0;
while(1) {
   #Move messages that can move out of quarantine to the forward queue.
   my $quarantinetime=time()-600;
   $ps3->execute($quarantinetime);
   $ps3->finish();
   #Do some sleeping to avoid locking issues.
   sleep(10);
   #Each hour cleanup stuff older than 8 days from database and filesystem.
   if ((time() - $lasttime) > 3600) {
      log_notice("Doing a cleanup round on the queues and event log");
      $lasttime=time();
      my $cleanuptime=time() - $longwk;
      $ps4->execute($cleanuptime);
      $ps4->finish();
      $ps5->execute($cleanuptime);
      $ps5->finish();
      $ps6->execute($cleanuptime);
      $ps6->finish();
      log_notice("Doing a cleanup round on the spool directory");
      open(FIND,"find $spooldir -type f -mtime +8|");
      while(<FIND>) {
         s/\r//g;
         chomp;
         if (/^${spooldir}\/?\d+\.\d+\.\d+\.\d+\/[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_]{22}\d{10}$/) {
            log_notice("Removing $_ from mailwall queue directory.");
            unlink($_);
         }
      }
      log_notice("Cleanup round finished, resuming normal operations.");
      my @localtime=localtime($lasttime);
      my $weekday=$localtime[6];
      if ($weekday == 0) {
          log_notice("It is sunday, lets see if we need to vacuum.");
          if (($lasttime-$lastbigtime) > 400000) {
              log_notice("Starting vacuum on database");
              $ps7->execute();
              $ps7->finish();
              $lastbigtime=$lasttime;
              log_notice("Vacuming done.");
          } else {
              log_notice("Skiping vacuming, already vacumed today.");
          }
      }
   }
   sleep(10);
   #Process all messages curently in the forward queue.
   my $rv = $ps1->execute();
   while (my ($recipient,$fspath,$person_id) = $ps1->fetchrow_array) {
       log_notice( "Processing $fspath for recipient $recipient\n");
       #Avoid race conditions with just removed files.
       if (-f "$fspath") {
       #Start a new outgoing SMTP connection and send out the message.
       my $smtp = Net::SMTP->new($smarthost);
       if ($smtp && ($smtp->mail("mailwall\@$topdomain")) && ($smtp->to($recipient)) && ($smtp->data())) { 
         if (open(DATA,$fspath)) {
	    my $inheader=1;
	    my $deleterestofheader=0;
            while(<DATA>) {
	       if ((/^$/) || (/^\r$/)) {
                  $inheader=0;
		  $smtp->datasend($_);
	       } else {
                  if ($inheader) {
		    #Unwrap header lines and remove lines starting with X- for security purposes. 
                    if (/^X/i) {
                       $deleterestofheader=1;
		    } elsif (($deleterestofheader) && (/^\s/)) {
                      $deleterestofheader=1; 
		    } else {
                      $deleterestofheader=0;
		      $smtp->datasend($_);
		    }
		  }
		  else {
                     $smtp->datasend($_);
		  }
	       }
	    }
	    if ($smtp->dataend()) {
	       log_notice("Message completed, deleting queue entry\n");
               $ps2->execute($recipient,$fspath);
	       $ps2->finish();
	    }
	 } else {
            log_warn("Problem opening $fspath\n");
	 }
       } else {
          log_warn("Problem with starting up SMTP connection\n");
       }
       if ($smtp) { $smtp->quit;}
       }
   }
   $ps1->finish();
   sleep(10);
}

