#!/usr/bin/perl
require 5.006;
use strict;
use MailWallDb;
use MailWallQueue;
package MailTemplates;
use Moose;
use Proc::DaemonLite qw(:all);

sub BUILD {
   my ($self) = @_;
   $self->{"forwarded"} = 
"From: noreply\@mailwall.local
To: [MW:SENDER]
Subject: MAILWALL:Message forwarded to [MW:RECIPIENT]

Your message [MW:MSGID] has directly been forwarded to the
local address [MW:RECIPIENT]. 

There is no action required on your part.

(This is an automated message sent by the MailWall-II proxy.)
";
   $self->{"delayed"} =
"From: queue\@mailwall.local
To: [MW:SENDER]
Subject: MAILWALL: Message to [MW:RECIPIENT] in DELAY queue (msg-id [MW:MSGID] )

Your message 

 Id: '[MW:MSGID]'
 To: '[MW:RECIPIENT]'
 Subject: '[MW:SUBJECT]'

is being delayed for inspection purposes.
This delay is used for detection and containment of mass mailing worms and viruses.
If all is well your message will be released from quarantine in about 10 minutes.

It is sugested that you respect this quarantine period and let the MailWall-II
system take care of things.

If the message has to be send directly, reply to this mail with 
an empty message body, leaving the subject line unchanged.

(This is an automated message sent by the MailWall-II proxy.)
";
  $self->{"unk"} =
"From: queue\@mailwall.local
To: [MW:SENDER]
Subject: MAILWALL: Message to [MW:RECIPIENT] in HOLD queue (msg-id [MW:MSGID] )


Your message 

 Id: '[MW:MSGID]'
 To: '[MW:RECIPIENT]'
 Subject: '[MW:SUBJECT]'

has been put in the HOLD queue.

You need to confirm that this message is legitimate , otherwise the message will
NOT be sent.

The reason your message has been put in the HOLD queue is that the recipient
[MW:RECIPIENT] is currently not tagged as an approved recipient in the 
Mailwall-II database. 

Mail to unknown recipients is not automatically forwarded in order 
to detect and contain any malware that might try to either phone-home, or might try
to spread itself or distribute spam from infected machines within the protected
network.

To confirm this message you should reply to this mail with an empty message body, 
leaving the subject line unchanged.

(This is an automated message sent by the MailWall-II proxy.)
";
  $self->{"binary"} =
"From: queue\@mailwall.local
To: [MW:SENDER]
Subject: MAILWALL: Binary message to [MW:RECIPIENT] in HOLD queue (msg-id [MW:MSGID] )

Your message 
 
 Id: '[MW:MSGID]' 
 To: '[MW:RECIPIENT]' 
 Subject: '[MW:SUBJECT]'
 
has been put in the HOLD queue and will not get send out without your aproval.

The reason your message has been put in the HOLD queue is that the message
contains binary data that possibly could hold malware or unintended confidential
(meta) data. The reason why binary mail content is not automatically forwarded is
to detect and contain any malware that might tryto spread itself or distribute spam 
from infected machines within the protected network.

To confirm this message you should reply to this mail with an empty message body,
leaving the subject line unchanged.

(This is an automated message sent by the MailWall-II proxy.)
";
  $self->{"unkandbinary"} =
"From: queue\@mailwall.local
To: [MW:SENDER]
Subject: MAILWALL: Binary message to [MW:RECIPIENT] in HOLD queue (msg-id [MW:MSGID] )

Your message 

 Id: '[MW:MSGID]'
 To: '[MW:RECIPIENT]'
 Subject: '[MW:SUBJECT]'

has been put in the HOLD queue and will not get send out without your aproval.

The reason your message has been put in the HOLD queue is twofold.
1) The message contains binary data that possibly could hold malware or unintended 
   confidential (meta) data.
2) The recipient [MW:RECIPIENT] is currently not marked as an approved recipient 
   in the Mailwall-II database.

The reason why mail to unknown recipients or mail containing binary content is not 
automatically forwarded is to detect and contain any malware that might try to either 
phone-home, or might try to spread itself or distribute spam from infected machines 
within the protected network.

To confirm this message you should reply to this mail with an empty message body,
leaving the subject line unchanged.

(This is an automated message sent by the MailWall-II proxy.)
";
  $self->{"unk2"} =
"From: peers\@mailwall.local
To: [MW:SENDER]
Subject: MAILWALL: Add [MW:RECIPIENT] to aproved peer database?

Recently you attempted to send out an e-mail to the recipient [MW:RECIPIENT].
Currently this recipient is not an 'aproved' recipient, meaning that each
single mail you send to this recipient will need to be manualy aproved.

If you expect to comunicate with this person or organisation on a regular basis,
it is sugested that you mark this recipient as an aproved recipient.

Please reply to this message with an empty message body, leaving the subject line 
unchanged.

Doing so will add [MW:RECIPIENT] to the aproved peer database, allowing future
email directed at [MW:RECIPIENT] to traverse the MailWall-II proxy without
manual intervention.

(This is an automated message sent by the MailWall-II proxy.)
";
}

sub sendFeedback {
  my ($self,$templatename,$msgid,$queue,$sender,$client,$recipient,$subject) =@_;
  my $message=$self->{$templatename};
  my $senderaddress=$sender->getAddress();
  my $recipientaddress = $recipient->getAddress();
  $message =~ s/\[MW:RECIPIENT\]/$recipientaddress/g;
  $message =~ s/\[MW:SENDER\]/$senderaddress/g;
  $message =~ s/\[MW:MSGID\]/$msgid/g;
  $message =~ s/\[MW:SUBJECT\]/$subject/g;
  my $queuemessage=$queue->newMessage(\$message,$sender,$client);
#  $queuemessage->addToQueue("forward",$sender,$client->getId(),$sender->getId());
  $queuemessage->addToQueue("forward",$sender,$client->getId(),0);
  return;
};

no Moose;
__PACKAGE__->meta->make_immutable;
