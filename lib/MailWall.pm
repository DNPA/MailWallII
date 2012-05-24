#!/usr/bin/perl
require 5.006;
use strict;
use MailWallDb;
use MailWallQueue;
use MessageIdFactory;
use MailWallSession;
package MailWall;
use Moose;


use Proc::DaemonLite qw(:all);

has 'db' => (
   isa => 'MailWallDb',
   is => 'rw'
);

has 'queue' => (
   isa => 'MailWallQueue',
   is => 'rw'
);


sub newsession {
  my ($self,$smtpsession) =@_;
  return new MailWallSession(smtpsession => $smtpsession,db => $self->{"db"},queue => $self->{"queue"});
};

no Moose;
__PACKAGE__->meta->make_immutable;
