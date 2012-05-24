#!/usr/bin/perl
require 5.006;
use strict;
use MailWallDb;
use MailTemplates;
use MailWallPerson;
use MailWallEventLog;
package CommandProcessor;
use Moose;
use Proc::DaemonLite qw(:all);

has 'db' => (
   isa => 'MailWallDb',
   is => 'ro',
);

has 'sender' => (
   isa => 'MailWallPerson',
   is => 'ro',
);

has 'eventlog' => (
   isa => 'MailWallEventLog',
   is => 'ro',
);

has 'templates' => (
   isa => 'MailTemplates',
   is => 'ro',
);

sub processQueueCommand {
   my ($self,$subject) = @_;
   log_notice("Processing queue command : $subject");
   if ($subject =~ /MAILWALL.*essage to (\S+) in \w+ queue \(msg-id (\S+)\s/) {
      my $recipient=$1; 
      my $msgid=$2;
      $self->db()->confirmMessage($msgid,$recipient,$self->sender());
      return "Message $msgid confirmed for $recipient";
   } else {
      return "Unrecognized command";
   }
}

sub processPeersCommand {
   my ($self,$subject) = @_;
   log_notice("Processing peers command : $subject");
   if ($subject =~ /Add (\S+) to aproved peer database/) {
      my $recipient=$1;
      $self->db()->addPermittedRecipient($recipient,$self->sender());
      return "Permitted recipient $recipient added to database";
   } else {
      return "Unrecognized command";
   }

}

sub addNewMailAddress {
  my ($self,$unixname,$mailaddress)=@_;
  my ($user,$domain)=split(/\@/,$mailaddress);
  my $rval=$self->db()->adminUpdateCommand("add_new_mail",$user,$domain,$unixname);
  return $rval;
}
sub addToList {
  my ($self,$unixname,$mailaddress)=@_;
  my ($user,$domain)=split(/\@/,$mailaddress);
  my $rval=$self->db()->adminUpdateCommand("add_list_mail",$user,$domain,$unixname);
  return $rval;
}
sub clearSystem {
  my ($self,$netnum,$hostnum)=@_;
  my $rval=$self->db()->adminUpdateCommand("clear_system",$netnum,$hostnum);
  return $rval;
}
sub createSystem {
  my ($self,$netnum,$hostnum)=@_;
  my $rval=$self->db()->adminUpdateCommand("create_system",$netnum,$hostnum);
  return $rval;
}
sub createListAddress { 
  my ($self,$mailaddress)=@_;
  my ($user,$domain)=split(/\@/,$mailaddress);
  my $rval=$self->db()->adminUpdateCommand("create_list_address",$user,$domain);
  return $rval;
}
sub deleteFromQueue {
   my ($self,$msgid)=@_;
   my $rval=$self->db()->adminUpdateCommand("delete_from_queue",$msgid);
   return $rval;
}
sub dropListAddress {
  my ($self,$mailaddress)=@_;
  my ($user,$domain)=split(/\@/,$mailaddress);
  my $rval=$self->db()->adminUpdateCommand("drop_list_address",$user,$domain);
  return $rval;
}
sub invalidCommand {
  my ($self,$subject,$message)=@_;
  return "Parsing error while processing command '$subject'\n $message\n";  
}
sub listAllEvents {
  my ($self)=@_;
  $self->db()->adminListCommand("list_all_events");
}
sub listAllSystems {
  my ($self)=@_;
  $self->db()->adminListCommand("list_all_systems");
}
sub listCompromizedSystems {
  my ($self)=@_;
  $self->db()->adminListCommand("list_all_compromized_systems");
}
sub listLists {
  my ($self)=@_;
  $self->db()->adminListCommand("list_lists");
}
sub listPersonEvents {
  my ($self,$user)=@_;
  $self->db()->adminListCommand("list_events_for_person",$user);
}
sub listPersonlessEvents {
  my ($self)=@_;
  $self->db()->adminListCommand("list_events_without_person");
}
sub listPersons {
  my ($self)=@_;
  $self->db()->adminListCommand("list_persons");
}
sub listPromisquousSystems {
  my ($self)=@_;
  $self->db()->adminListCommand("list_systems_promisq");
}
sub listQueueNames {
  my ($self)=@_;
  return "The known queue names are:\n\n* forward\n* delay\n* hold\n\n";
}
sub listQueue {
  my ($self,$queuename)=@_;
  $self->db()->adminListCommand("list_queue",$queuename);
}
sub listRoamingPersons {
  my ($self)=@_;
  $self->db()->adminListCommand("list_persons_roaming");
}
sub listSystemEvents {
  my ($self,$netnum,$hostnum)=@_;
  $self->db()->adminListCommand("list_events_for_system",$netnum,$hostnum);
}
sub listSystemlessEvents {
  my ($self)=@_;
  $self->db()->adminListCommand("list_events_without_system");
}
sub listUserAdresses {
  my ($self,$unixname)=@_;
  $self->db()->adminListCommand("list_adresses_user",$unixname);
}
sub moveToOtherQueue {
  my ($self,$msgid,$newqueue)=@_;
  my $rval=$self->db()->adminUpdateCommand("move_to_other_queue",$newqueue,$msgid);
  return $rval;
}
sub newPerson {
  my ($self,$unixname,$fullname)=@_;
  my $rval=$self->db()->adminUpdateCommand("new_person",$unixname,$fullname);
  return $rval;
}

#FIXME
sub listUsersForSystem {
   my ($self,$netnum,$hostnum)=@_;
   $self->db()->adminListCommand("list_users_for_system",$netnum,$hostnum);
};

sub listSystemsForUser {
   my ($self,$unixname) = @_;
   $self->db()->adminListCommand("list_system_for_user",$unixname);
}

sub listAllSystemUsers{
   my ($self)=@_;
   $self->db()->adminListCommand("list_system_users");
}

sub newSystemUser {
   my ($self,$unixname,$netnum,$hostnum) = @_;
   $self->db()->adminUpdateCommand("add_new_systemuser",$unixname,$netnum,$hostnum);
}

sub deleteSystemUser {
   my ($self,$unixname,$netnum,$hostnum) = @_;
   $self->db()->adminUpdateCommand("delete_systemuser",$unixname,$netnum,$hostnum);
}

sub invokeBatch {
   my ($self,$reportname,$whaton,$attribute) = @_;
   $self->db()->invokeBatch($reportname,$whaton,$attribute);
}

sub processUpdateForm {
  my ($self,$whatoff,$data) = @_;
  $self->db()->processUpdateForm($whatoff,$data);
}






sub processHelp {
  my ($self)=@_;
  return "In order to administrate the MailWall-II sqlite database, you can give commands by puting
them in your e-mail subject. The mail should be directed at 'admini\@mailwall.local'.

The folowing commands are available (or will be shortly).

HELP                              :  Returns this text.
PERSON LIST                       :  Returns a list of defined persons in the database.
PERSON LIST ROAMING               :  Same as 'PERSON LIST', but returns only roaming users.
PERSON NEW <unixname> <fullname>  :  Creates a new person record.
PERSON ROAMING <unixname>         :  Sets a person roaming flag to true.
PERSON NO ROAMING <unixname>      :  Sets a person roaming flag to false.
SYSTEM LIST                       :  Returns a list of all system records.
SYSTEM LIST COMP                  :  Same as 'SYSTEM LIST', but only returns systems marked as compromized.
SYSTEM LIST PROM                  :  Same as 'SYSTEM LIST', but only returns systems marked as promisquous.
SYSTEM NEW <netnum> <hostnum>     :  Created a new system record.
SYSTEM CLEAR <netnum> <hostnum>   :  Sets a system compromized flag to false.
SYSTEM PROM <netnum> <hostnum>    :  Sets a system promisquous flag to true.
SYSTEM NO PROM <netnum> <hostnum> :  Sets a system promisquous flag to false.
ADDRESS LIST <unixname>           :  Returns a list of adresses defined for a given person.
ADDRESS ADD <unixname> <address>  :  Add an e-mail address for a given person.
ADDRESS DEL <address>             :  Remove an e-mail address.
LIST LIST                         :  Returns a list of all defined mailinglists.
LIST NEW  <address>               :  Creates a new mailinglist record.
LIST ADD <unixname> <address>     :  Add a user to a mailinglist. (Note: ONLY relevant if list may be set to shared)
LIST SHARED <address>             :  Set the shared flag for the list to 'true', meaning it can be used as From: address
                                     by its members.
LIST NO SHARED <address>          :  Set the shared flag for the list to 'false'.
QUEUE LIST                        :  Returns the names of the queues.
QUEUE LIST <queuename>            :  Lists all messages in a given queu.
QUEUE MOVE <que1> <msgid> <que2>  :  Move a given message from one queue to an other.
QUEUE DEL  <msgid>                :  Remove a message from all queues.
EVENT LIST                        :  List all system/person combination involved in events.
EVENT LIST PERSON <unixname>      :  List all events involving a given user.
EVENT LIST PERSON NON             :  List all events that don't have a specific user atached to them.
EVENT LIST SYSTEM <net> <host>    :  List all events involving a given host.
EVENT LIST SYSTEM OTHER           :  List all events not involving a known host.
SYSTEMUSER LIST                   :  List all person/user combinations.
SYSTEMUSER LIST <unixname>        :  List all systems that a given person is allowed to work from.
SYSTEMUSER LIST <netnum> <hostnum>:  List all persons that are allowed on a given system.
SYSTEMUSER NEW <unixname>  <netnum> <hostnum>
                                  :  Add a new explicit permission for a person to work from an IP.
SYSTEMUSER DEL <unixname>  <netnum> <hostnum>
                                  :  Delete an explicit permission for a person to work from an IP.
COMPOSIT REPORT USER <unixname>   :  Get a report for a given person
COMPOSIT DELETE USER <unixname>   :  Run all queries needed to delete everyting for a specific user.
COMPOSIT EDIT USER <unixname>     :  Fetch a pre-filled form for editing a user OR an empty form for creating a non existing user.
COMPOSIT UPDATE USER              :  Process a filled out form for creation or updating of a user.
";
}
sub removeFromList {
  my ($self,$unixname,$mailaddress)=@_;
  my ($user,$domain)=split(/\@/,$mailaddress);
  $self->db()->adminUpdateCommand("remove_from_list",$unixname,$user,$domain);
}
sub setListAsShared {
  my ($self,$mailaddress,$val)=@_;
  my ($user,$domain)=split(/\@/,$mailaddress);
  $self->db()->adminUpdateCommand("set_list_as_shared",$val, $user,$domain);
}
sub setPersonRoaming {
  my ($self,$unixname,$val)=@_;
  $self->db()->adminUpdateCommand("set_person_roaming",$val,$unixname);
}
sub setPromisquous {
  my ($self,$netnum,$hostnum,$val)=@_;
  $self->db()->adminUpdateCommand("set_host_promisquous",$val,$netnum,$hostnum);
}
sub processAdminCommand {
   my ($self,$subject,$data) = @_;
   $subject =~ s/^\s+//;
   my ($command,@arguments) = split(/\s+/,$subject);
   unless ($command) {
     $self->invalidCommand($subject,"No command specified.");
     return;
   }
   $command = lc($command);
   if ($command eq "help") {
     $self->processHelp();
   } elsif ($command eq "person") {
      my $subcmd=lc(shift(@arguments));
      unless ($subcmd) {
        $self->invalidCommand($subject,"No sub command specified for PERSON command;.");
        return;
      }
      if ($subcmd eq "list") {
         my $filter=lc(shift(@arguments));
	 if ($filter) {
           if ($filter eq "roaming") {
              $self->listRoamingPersons();
	   } else {
              $self->invalidCommand($subject,"Invalid filter '$filter' for PERSON LIST command.");
	   }
	 } else {
           $self->listPersons();
	 }
      } elsif ($subcmd eq "new") {
         my $unixname = lc(shift(@arguments));
	 my $fullname = join(" ",@arguments);
	 if ($fullname) {
            $self->newPerson($unixname,$fullname);
	 } else {
           $self->invalidCommand($subject,"Insuficient arguments for PERSON NEW command.");
	 }
      } elsif ($subcmd eq "roaming") {
         my $unixname = lc(shift(@arguments));
	 if ($unixname) {
            $self->setPersonRoaming($unixname,'true');
	 } else {
            $self->invalidCommand($subject,"Insufficient arguments for PERSON ROAMING command.");
	 }
      } elsif ($subcmd eq "no") {
         if (lc(shift(@arguments)) eq "roaming") {
           my $unixname = lc(shift(@arguments));
           if ($unixname) {
              $self->setPersonRoaming($unixname,'false');
	   } else {
              $self->invalidCommand($subject,"Insufficient arguments for PERSON NO ROAMING command"); 
	   }
	 } else {
           $self->invalidCommand($subject,"Unknown subcommand for PERSON NO");
	 }
      } else {
         $self->invalidCommand($subject,"Unknown subcommand for PERSON");
      }
   } elsif ($command eq "system") {
      my $subcmd=lc(shift(@arguments));
      unless ($subcmd) {
        $self->invalidCommand($subject,"No sub command specified for SYSTEM command;.");
        return;
      }
      if ($subcmd eq "list") {
         my $filter=lc(shift(@arguments));
	 if ($filter) {
            if ($filter eq "COMP") {
              $self->listCompromizedSystems();
	    } elsif ($filter eq "PROM") {
              $self->listPromisquousSystems();
	    } else {
              $self->invalidCommand($subject,"Invalid filter '$filter' for SYSTEM LIST command.");
	    }
	 } else {
            $self->listAllSystems();
	 }
      } elsif ($subcmd eq "new") {
         my $netnum=lc(shift(@arguments))+0;
	 my $hostnum=lc(shift(@arguments))+0;
	 if ($hostnum) {
            $self->createSystem($netnum,$hostnum);
	 } else {
            $self->invalidCommand($subject,"Insufficient arguments for SYSTEM NEW command");
	 }
      } elsif ($subcmd eq "clear") {
         my $netnum=lc(shift(@arguments))+0;
         my $hostnum=lc(shift(@arguments))+0;
         if ($hostnum) {
            $self->clearSystem($netnum,$hostnum);
	 } else {
            $self->invalidCommand($subject,"Insufficient arguments for SYSTEM CLEAR command");
	 }
      } elsif ($subcmd eq "prom") {
         my $netnum=lc(shift(@arguments))+0;
	 my $hostnum=lc(shift(@arguments))+0;
         if ($hostnum) {
            $self->setPromisquous($netnum,$hostnum,"true");
	 } else {
            $self->invalidCommand($subject,"Insufficient arguments for SYSTEM PROM command");
	 }
      } elsif ($subcmd eq "no") {
        if (lc(shift(@arguments)) eq "prom") {
           my $netnum=lc(shift(@arguments))+0;
	   my $hostnum=lc(shift(@arguments))+0;
	   if ($hostnum) {
              $self->setPromisquous($netnum,$hostnum,"false");
	   } else {
              $self->invalidCommand($subject,"Insufficient arguments for SYSTEM NO PROM command");
	   }
	} else {
          $self->invalidCommand($subject,"Unknown subcommand for SYSTEM NO");
	}
      } else {
         $self->invalidCommand($subject,"Unknown subcommand for SYSTEM.");
      }
   } elsif ($command eq "address") {
     my $subcmd=lc(shift(@arguments));
     unless ($subcmd) {
        $self->invalidCommand($subject,"No sub command specified for ADDRESS command;.");
        return;
     }
     if ($subcmd eq "list") {
         my $unixname=lc(shift(@arguments));
	 if ($unixname) {
             $self->listUserAdresses($unixname);
	 } else {
            $self->invalidCommand($subject,"Insufficient arguments for ADDRESS LIST command");
	 }
     } elsif ($subcmd eq "add") {
         my $unixname=lc(shift(@arguments));
	 my $mailaddress=lc(shift(@arguments));
	 if ($mailaddress) {
             $self->addNewMailAddress($unixname,$mailaddress);
	 } else {
            $self->invalidCommand($subject,"Insufficient arguments for ADDRESS ADD");
	 }
     } else {
       $self->invalidCommand($subject,"Unknown subcommand for ADDRESS.");
     }
   } elsif ($command eq "list") {
     my $subcmd=lc(shift(@arguments));
     if ($subcmd eq "list") {
        $self->listLists();
     } elsif ($subcmd eq "new") {
        my $mailaddress=lc(shift(@arguments));
	if ($mailaddress) {
	   $self->createListAddress($mailaddress);
	} else {
           $self->invalidCommand($subject,"Insufficient arguments for LIST NEW");
	}
     } elsif ($subcmd eq "add") {
        my $unixname=lc(shift(@arguments));
        my $mailaddress=lc(shift(@arguments));
	if ($mailaddress) {
           $self->addToList($unixname,$mailaddress);
	} else {
           $self->invalidCommand($subject,"Insufficient arguments for LIST ADD");
	}
     } elsif ($subcmd eq "del") {
        my $unixname=lc(shift(@arguments));
	my $mailaddress=lc(shift(@arguments));
	if ($mailaddress) {
           $self->removeFromList($unixname,$mailaddress);
	} else {
          $self->invalidCommand($subject,"Insufficient arguments for LIST DEL");
	}
     } elsif ($subcmd eq "shared") {
        my $mailaddress=lc(shift(@arguments));
	if ($mailaddress) {
           $self->setListAsShared($mailaddress,"true");
	} else {
           $self->invalidCommand($subject,"Insufficient arguments for LIST SHARED");
	}
     } elsif ($subcmd eq "no") {
       my $subsubcmd=lc(shift(@arguments));
       if ($subsubcmd eq "shared") {
          my $mailaddress=lc(shift(@arguments));
	  if ($mailaddress) {
             $self->setListAsShared($mailaddress,"false");
	  } else {
            $self->invalidCommand($subject,"Insufficient arguments for LIST NO SHARED");
	  }
       } else {
         $self->invalidCommand($subject,"Unknown subcommand for LIST NO");
       }
     } else {
         $self->invalidCommand($subject,"Unknown subcommand for LIST");
     }
   } elsif ($command eq "queue") {
     my $subcmd=lc(shift(@arguments));
     unless ($subcmd) {
        $self->invalidCommand($subject,"No sub command specified for QUEUE command;.");
        return;
      }
     if ($subcmd eq "list") { 
        my $queuename=lc(shift(@arguments));
	if ($queuename) {
           $self->listQueue($queuename);
	} else {
           $self->listQueueNames();
	}
     } elsif ($subcmd eq "move") {
	my $msgid=lc(shift(@arguments));
	my $newqueue=lc(shift(@arguments));
	if ($newqueue) {
           $self->moveToOtherQueue($msgid,$newqueue);
	} else {
	   $self->invalidCommand($subject,"Insufficient arguments for QUEUE MOVE");
	}
     } elsif ($subcmd eq "del") {
	my $msgid=lc(shift(@arguments));
	if ($msgid) {
          $self->deleteFromQueue($msgid);
	} else {
          $self->invalidCommand($subject,"Insufficient arguments for QUEUE DEL");
	}
     } else {
        $self->invalidCommand($subject,"Unknown subcommand for QUEUE");
     }
   } elsif ($command eq "event") {
     my $subcmd=lc(shift(@arguments));
     unless ($subcmd) {
        $self->invalidCommand($subject,"No sub command specified for EVENT command;.");
        return;
      }
     if ($subcmd eq "list") {
        my $object=lc(shift(@arguments));
	if ($object) {
	  if ($object eq "person") {
              my $user = lc(shift(@arguments));
	      if ($user) {
	        if ($user eq "non") {
                    $self->listPersonlessEvents();
	        } else {
                    $self->listPersonEvents($user)
		}
              } 
	      else {
                 $self->invalidCommand($subject,"Insufficient arguments for EVENT LIST PERSON");
	      }
	  } elsif ($object eq "system") {
             my $netnum=lc(shift(@arguments));
	     if ($netnum) {
                if ($netnum eq "other") {
                    $self->listSystemlessEvents();
		} else {
		   my $hostnum=lc(shift(@arguments));
		   if ($hostnum) {
                     $self->listSystemEvents($netnum,$hostnum);
		   } else {
                      $self->invalidCommand($subject,"Insufficient arguments for EVENT LIST SYSTEM");
		   }
		}
	     } else {
                $self->invalidCommand($subject,"Insufficient arguments for EVENT LIST SYSTEM");
	     }
	  } else {
            $self->invalidCommand($subject,"Unknown filter for QUEUE LIST command");
	  }
	} else {
          $self->listAllEvents();
	}
     } else {
        $self->invalidCommand($subject,"Unknown subcommand for EVENT");
     }
   } elsif ($command eq "systemuser") {
      my $subcmd=lc(shift(@arguments));
      unless ($subcmd) {
        $self->invalidCommand($subject,"No sub command specified for PERSON command;.");
        return;
      }
      if ($subcmd eq "list") {
         my $unixname=lc(shift(@arguments));
         if ($unixname) {
           if ($unixname =~ /^\d+$/) {
              my $netnum=$unixname;
              if (($netnum < 1) || ($netnum > 254)) {
                  $self->invalidCommand($subject,"Invalid net number field for SYSTEMUSER command, value $netnum out of range (1 .. 254).");
              } else {
                my $hostnum=lc(shift(@arguments));
                if ($hostnum) {
                 if ($hostnum =~ /^\d+$/) { 
                    if (($hostnum < 1) || ($hostnum > 254)) {
                       $self->invalidCommand($subject,"Invalid host number field for SYSTEMUSER command, value $hostnum out of range (1 .. 254).");
                    } else {
                       $self->listUsersForSystem($netnum,$hostnum);
                    }
                 } else {
                    $self->invalidCommand($subject,"Invalid host number field for SYSTEMUSER command, not a number.");
                 }
                } else {
                  $self->invalidCommand($subject,"Insufficient arguments for SYSTEMUSER LIST $netnum <hostnum>");   
                }
              }
           } else {
               $self->listSystemsForUser($unixname);
           }
         } else {
            $self->listAllSystemUsers();
         }
      } elsif ($subcmd eq "new") {
        my $unixname = lc(shift(@arguments)); 
        my $netnum =   lc(shift(@arguments));
        my $hostnum =  lc(shift(@arguments));
        if ($hostnum) {
           $self->newSystemUser($unixname,$netnum,$hostnum);
        } else {
           $self->invalidCommand($subject,"Insufficient arguments for SYSTEMUSER NEW");
        }
      }  elsif ($subcmd eq "del") {
         my $unixname = lc(shift(@arguments));
         my $netnum =   lc(shift(@arguments));
         my $hostnum =  lc(shift(@arguments));
         if ($hostnum) {
              $self->deleteSystemUser($unixname,$netnum,$hostnum);
         } else {
             $self->invalidCommand($subject,"Insufficient arguments for SYSTEMUSER DEL");
         }
      } else {
         $self->invalidCommand($subject,"Invalid sub command '$subcmd' for  SYSTEMUSER command.");
      }
   } elsif ($command eq "composit") {
      my $subcmd=lc(shift(@arguments));
      unless ($subcmd) {
        $self->invalidCommand($subject,"No sub command specified for PERSON command;.");
        return;
      }
      if ($subcmd eq "report") {
         my $whaton=lc(shift(@arguments));
         if ($whaton) {
           my $attribute=lc(shift(@arguments));
           $self->invokeBatch("report",$whaton,$attribute);
         } else {
           $self->invalidCommand($subject,"Invalid argument count for COMPOSIT REPORT command.");
         }
      } elsif ($subcmd eq "delete") {
          my $whatoff=lc(shift(@arguments));
          my $attribute=lc(shift(@arguments));
          if ($attribute) {
             $self->invokeBatch("delete",$whatoff,$attribute);
          } else {
            $self->invalidCommand($subject,"Invalid argument count for COMPOSIT DELETE command.");
          }
      } elsif ($subcmd eq "edit") {
          my $whatoff=lc(shift(@arguments));
          my $attribute=lc(shift(@arguments));
          if ($attribute) {
             $self->invokeBatch("edit",$whatoff,$attribute);
          } else {
            $self->invalidCommand($subject,"Invalid argument count for COMPOSIT EDIT command.");
          }

      } elsif ($subcmd eq "update") {
          my $whatoff=lc(shift(@arguments));
          if ($whatoff) {
              $self->processUpdateForm($whatoff,$data);
          } else {
             $self->invalidCommand($subject,"Invalid argument count for COMPOSIT UPDATE command.");
          }
      } else {
          $self->invalidCommand($subject,"Invalid sub command '$subcmd' for  COMPOSIT command.");
      } 
   } else {
     $self->invalidCommand($subject,"Unknown command '$command'\n");
   }
}

sub dataToSubject {
  my ($self,$dataref)=@_;
  my ($header) = split(/\n\r?\n/,$$dataref);
  $header =~ s/\r//mg;
  $header =~ s/\n\s+/ /mg;
  my @headers = split(/\n/,$header);
  foreach my $line (@headers) {
      if ($line =~ /^Subject\s*:\s*(\S.*)$/) {
         return $1;
      }
  }
}


no Moose;
__PACKAGE__->meta->make_immutable;


