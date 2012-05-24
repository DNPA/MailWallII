#!/usr/bin/perl
require 5.006;
use strict;
use MailWallDb;
package MailWallEventLog;
use Moose;
use Proc::DaemonLite qw(:all);

has 'db' => (
   isa => 'MailWallDb',
   is => 'ro'
);

has 'clientip' => (
   isa => 'Str',
   is => 'ro'
);

sub setClient {
  my ($self,$client)=@_;
  $self->{"client"}=$client;
}

sub setFrom {
 my ($self,$from)=@_;
 $self->{"from"}=$from;
}

sub setSender {
  my ($self,$sender)=@_;
  $self->{"sender"}=$sender;
}

sub addmsg  {
  my ($self,$msg)=@_;
  my $client_id=0;
  my $sender_id=0;
  my $from=$self->{"from"};
  my $sender=$self->{"sender"};
  if ($sender) {
     $sender_id=$sender->getId();
  }
  my $client=$self->{"client"};
  if ($client) {
     $client_id=$client->getId();
  }
  unless ($client_id) { $msg .= " [ip:" . $self->clientip() . "]"; }
  unless ($sender_id) { 
     if ($from) {  $msg .= " [mail:" . $from . "]"; } 
  }
  my $db=$self->db();
  $db->addToEventLog($client_id,$sender_id,$msg,time());
}

no Moose;
__PACKAGE__->meta->make_immutable;
