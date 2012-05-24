#!/usr/bin/perl
require 5.006;
use strict;
use MailWallDb;
use MailWallQueue;
use MailWallEventLog;
use MailTemplates;
use CommandProcessor;
package MailWallSession;
use Moose;
use Proc::DaemonLite qw(:all);

has 'db' => (
   isa => 'MailWallDb',
   is => 'ro',
);

has 'queue' => (
   isa => 'MailWallQueue',
   is => 'ro',
);

has 'smtpsession' => (
   isa => 'Ref',
   is => 'ro',
);

has 'mailtemplates' => (
   isa => 'MailTemplates',
   is => 'ro',
   default => sub { return new MailTemplates();},
);

#Get called on SMTP HELO, at what point we look at the client if we want to deny it access by itself.
sub validatePeer {
  my ($self,$name) =@_;
  my $smtpsession=$self->smtpsession();
  my $peer=$smtpsession->{"peer"};
  my $db=$self->db();
  $self->{"client"} = $db->lookupClient($peer);
  my $client=$self->{"client"};
  $self->{"eventlog"}=$db->createBasicEventLog($peer);
  my $eventlog=$self->{"eventlog"};
  #deny unknown clients.
  unless (defined $self->{"client"}) {
    $eventlog->addmsg("message bounced from unregistered machine");
    return(0, 554, "Your IP $peer is not a registered client for this mail server.");
  }
  $eventlog->setClient($self->{"client"});
  #deny trojanized clients.
  if ($self->{"client"}->isTrojanized()) {
    $eventlog->addmsg("message bounced from client marked as compromized");
    return(0, 554, "Your IP $peer has been marked as being trojanized.");
  }
  return(1);
};

#Gets called on SMTP MAIL FROM, at what point we look at the sender if we want to deny it access combined with the client.
sub validateFrom {
  my ($self,$from) =@_;
  my $db=$self->db();
  my $client=$self->{"client"};
  my $client_ip=$client->getIp();
  my $eventlog=$self->{"eventlog"};
  $eventlog->setFrom($from);
  $self->{"sender"} = $db->lookupSender($from);
  my $sender=$self->{"sender"};
  #deny unknown senders.
  unless ($sender) {
      $eventlog->addmsg("Message bounced from unknown sender"); 
      return(0, 554, "$from: Sender address rejected.");
  }
  $eventlog->setSender($sender);
  my $msgcount=$client->getMsgCount($sender);
  #deny messages when a flood of messages is detected.
  if (($msgcount > 10) || ($client->isPromisq() && ($msgcount > 100))) {
      #also park existing messages from this client in the hold queue and mark the client as trojanized.
      $client->setTrojanized();
      $client->parkDelayQueue();
      $eventlog->addmsg("machine has been marked as trojanized"); 
      return(0, 554, "Your IP $client_ip has being marked as trojanized.");
  }
  #Allow promisquous clients and roeming users.
  if ($client->isPromisq() || $sender->isRoaming()) {
     $self->{"commandprocessor"} = new CommandProcessor(db => $db,sender => $sender,eventlog => $eventlog,templates => $self->mailtemplates());
     return(1,250,"2.1.0 OK Sending mail allowed by broad rule.");
  }
  #Also allow explicitly allowed combinations.
  if ($client->isPermittedSender($sender)) {
     $self->{"commandprocessor"} = new CommandProcessor(db => $db,sender => $sender,eventlog => $eventlog,templates => $self->mailtemplates());
     return(1,250,"2.1.0 <" . $sender->getAddress() . ">... Sender ok");
  }
  #Deny all others.
  $eventlog->addmsg("Message bounced for foreign non roaming user on non promisq client.");
  return(0, 554, "$from: Sender address rejected for client.");
};

#Gets called on SMTP RCPT TO.
sub validateRecipient {
  my ($self,$recipientaddress) =@_;
  my $client=$self->{"client"};
  my $eventlog=$self->{"eventlog"};
  my $sender=$self->{"sender"};
  #Seperate commands from regular trafic, and make sure the two are not mixed for a single message.
  if ($recipientaddress =~ /(\w+)\@mailwall\.local/) { 
     if (defined($self->{"processingmode"})) {
       return(0,554,"Attempting to combine normal with special addresses from a single mail.");
     }
     $self->{"processingmode"}=$1;
     return(1,250,"2.1.5 recipient $recipientaddress OK, validation delayed.");
  } else {
     if ($self->{"processingmode"} && ($self->{"processingmode"} ne "relay")) {
        return(0,554,"Attempting to combine normal with special addresses from a single mail.");
     }
     $self->{"processingmode"}="relay";
     my $db=$self->db();
     my $recipient=$db->newMailWallRecipient($recipientaddress,$sender->getId());
     if ($recipient->isLocal()) { 
         return(1,250,"2.1.5 recipient $recipientaddress OK, using direct forwarding.");
     } 
     if ($recipient->isRemote()) {
         return(1,250,"2.1.5 recipient $recipientaddress OK, using defered forwarding.");
     }
     return(1,250,"2.1.5 recipient $recipientaddress OK, unknown recipient, requires confirmation.");
  }
};

#Gets called ones all message data is received.
#CODEREVIEW JCW: Testen met grote berichten.
#CODEREVIEW JCW: Mogelijkheid om met emails te besturen biedt hack mogelijkheden: Testen.
#CODEREVIEW JCW: Je geeft heel veel info terug.
sub queueMessage {
  my ($self,$data) =@_;
  my $db=$self->db();
  my $client=$self->{"client"};
  my $sender=$self->{"sender"};
  my $eventlog=$self->{"eventlog"};

  my $commandprocessor = $self->{"commandprocessor"};
  my $subject=$commandprocessor->dataToSubject($data);
  if ($subject =~ /^$/) {
     log_warn("Message with no subject");
  }
  my $smtpsession=$self->smtpsession();
  my @recipients = $smtpsession->get_recipients();
  unless(@recipients) {
      return(0, 554, 'Error: no valid recipients');
  }
  my $processingmode=$self->{"processingmode"};
  if ($processingmode eq "relay") {
    #Processing of regular trafic.
    my $queue=$self->queue();
    #Create a new message in the filesystem.
    my $queuemessage=$queue->newMessage($data,$sender,$client);
    my $msgid=$queuemessage->getMsgId();
    my $hasbinary=$queuemessage->hasBinary();
    foreach my $recipientaddress (@recipients) {
       my $recipient=$db->newMailWallRecipient($recipientaddress,$sender->getId());
       if ($recipient->isOk() && (!$hasbinary)) {
         if ($recipient->isLocal()) {
	    #Add the message to the queue for each local known recipient.
            $queuemessage->addToQueue("forward",$recipient,$client->getId(),$sender->getId());
	    $eventlog->addmsg("Recipient $recipientaddress local, putting $msgid into FORWARD queue for $recipientaddress");
	    #Basic feedback to the user.
	    $self->mailtemplates()->sendFeedback("forwarded",$msgid,$queue,$sender,$client,$recipient,$subject);
	 } else {
	    #Add the message to the delay queue for known validated non local recipients.
	    $queuemessage->addToQueue("delay",$recipient,$client->getId(),$sender->getId());
	    $eventlog->addmsg("Recipient $recipientaddress not local, putting $msgid into DELAY queue for $recipientaddress");
	    #Feedback with the posibility to speed things up.
	    $self->mailtemplates()->sendFeedback("delayed",$msgid,$queue,$sender,$client,$recipient,$subject);
	 }
       } else {
          #Put the message into the hold queue for unknown or unvalidated recipients.
          $queuemessage->addToQueue("hold",$recipient,$client->getId(),$sender->getId());
	  #Find out what feedback to send to the user, allowing the user to force the blocked message truegh.
          unless ($recipient->isOk()) {
             if ($hasbinary) {
                $eventlog->addmsg("Unknown recipient $recipientaddress AND binary content, putting $msgid into HOLD queue for $recipientaddress");
		$self->mailtemplates()->sendFeedback("unkandbinary",$msgid,$queue,$sender,$client,$recipient,$subject);
	     } else {
                $eventlog->addmsg("Unknown recipient $recipientaddress, putting $msgid into HOLD queue for $recipientaddress");
		$self->mailtemplates()->sendFeedback("unk",$msgid,$queue,$sender,$client,$recipient,$subject);
	     }
	     $self->mailtemplates()->sendFeedback("unk2",$msgid,$queue,$sender,$client,$recipient,$subject);
	  } else {
             $eventlog->addmsg("Binary content, putting $msgid into HOLD queue for $recipientaddress");
	     $self->mailtemplates()->sendFeedback("binary",$msgid,$queue,$sender,$client,$recipient,$subject);
	  }
       }
    }
    return (1);
  } else {
     #Processing of command subjects.
     if ($db->adminOk($client,$sender,$processingmode)) {
        my $reply;
	if ($processingmode eq "queue") {
            $reply=$commandprocessor->processQueueCommand($subject);
	} elsif ($processingmode eq "peers") {
	    $reply=$commandprocessor->processPeersCommand($subject);
	} elsif ($processingmode eq "admin") {
           $reply=$commandprocessor->processAdminCommand($subject,$data);
        } else {
           return(0,554,"Unable to process mail to unrecognized special address.");
	}
	if ($reply) {
	  #If we get a reply from processing we send it back to the user.
	  my $header="From: noreply\@mailwall.local\nTo: " . $sender->getAddress() . "\nSubject: [MAILWALL] Command response for : $subject\n\n";
          my $message=$header . "The result from your command $subject is as follows: \n\n" . $reply;
          my $queuemessage=$self->queue()->newMessage(\$message,$sender,$client);
	  $queuemessage->addToQueue("forward",$sender,$client->getId(),0);
	}
	return (1);
     } else {
        $eventlog->addmsg("Attempt to perform a $processingmode administration task without proper rights");
	return(0,554,"Insufficient privileges for sending mail to special address.");
     }
  }
};

sub resetSession {
  return (1);
};

sub postQuit {
  return (1);
};

no Moose;
__PACKAGE__->meta->make_immutable;
