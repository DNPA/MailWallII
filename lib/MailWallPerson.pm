#!/usr/bin/perl
require 5.006;
use strict;
use MailWallDb;
package MailWallPerson;
use Moose;
use Proc::DaemonLite qw(:all);

has 'domain' => (
   isa => 'Str',
   reader => 'getDomain',
);

has 'username' => (
   isa => 'Str',
   reader => 'getUserName',
);

has 'personid' => (
   isa => 'Int',
   reader => 'getId',
);

has 'db' => (
   isa => 'MailWallDb',
   is => 'ro',
);

has 'roaming' => (
   isa => 'Bool',
   reader => 'isRoaming',
);

sub getAddress {
  my ($self) = @_;
  my $email= $self->getUserName() . "\@" . $self->getDomain();
}

no Moose;
__PACKAGE__->meta->make_immutable;
