#!/usr/bin/perl
require 5.006;
use strict;
use MailWallDb;
package MailWallClient;
use Moose;
use Proc::DaemonLite qw(:all);

has 'ip' => (
   isa => 'Str',
   reader => 'getIp',
);

has 'id' => (
   isa => 'Int',
   reader => 'getId',
);

has 'db' => (
   isa => 'MailWallDb',
   is => 'ro',
);

has 'promesq' => (
   isa => 'Bool',
   reader => 'isPromisq',
);

has 'trojanized' => (
   isa => 'Bool',
   reader => 'isTrojanized'
);

has 'net' => (
   isa => 'Int',
   reader => 'getNetNum'
);

has 'host' => (
   isa => 'Int',
   reader => 'getHostNum'
);

sub getMsgCount {
  my ($self,$sender) =@_;
  my $db=$self->db();
  my $sender_id=$sender->getId();
  return $db->messageCount($self->getId(),$sender_id,time());
};

sub setTrojanized {
  my ($self) =@_;
  my $db=$self->db();
  $db->setTrojanized($self->getId());
  log_warning("A system has been marked as trojanized");
  return;
};

sub parkDelayQueue {
  my ($self) =@_;
  my $db=$self->db();
  $db->parkDelayQueue($self->getId());
  return;
}

sub isPermittedSender {
  my ($self,$sender) =@_;
  my $sender_id=$sender->getId();
  my $db=$self->db();
  return $db->lookupWsUser($self->getId(),$sender_id);
}

no Moose;
__PACKAGE__->meta->make_immutable;
