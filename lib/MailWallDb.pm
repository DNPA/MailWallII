#!/usr/bin/perl
require 5.006;
use strict;
use DBI;
use MailWallEventLog;
use MailWallClient;
use MailWallPerson;
use MailWallPeer;

package MailWallDb;
use Moose;
use Proc::DaemonLite qw(:all);

has 'dbpath' => (
    is  => 'rw',
    isa => 'Str',
);

has 'adminip' => (
    is  => 'ro',
    isa => 'Str',
);

has 'adminuser' => (
    is  => 'ro',
    isa => 'Str',
);

has 'basenet' => (
    is  => 'ro',
    isa => 'Str',
);

sub BUILD {
    my $self = shift;
    my $path = $self->dbpath;
    my $dbh =
      DBI->connect( "dbi:SQLite:dbname=$path", "", "",
        { RaiseError => 1, AutoCommit => 1 } )
      || die "Problem with sqlite db at $path";

#Scale up the default busy_timeout so we shouldn't get them if the forwarde locks the database for long.
    my $timeout = $dbh->func('busy_timeout');
    $timeout *= 10;
    $dbh->func( $timeout, 'busy_timeout' );
    $self->{"dbh"} = $dbh;

    #Define a whole lot of prepared statements for later use.
    $self->{"q_set_trojanized"} =
      $dbh->prepare("update system set trojanized='true' where system_id=?")
      or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_lookup_client"} = $dbh->prepare(
"select system_id,promesq,trojanized from system where net=? and ip=? limit 1"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_lookup_sender"} = $dbh->prepare(
"select person.person_id,roaming from person,addressuser where person.person_id=addressuser.person_id and address_id in (select address_id from address where username=? and domain=? and (shared='true' or list='false')) limit 1"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_lookup_wsuser"} = $dbh->prepare(
        "select count(*) > 0 from systemuser where system_id=? and person_id=?")
      or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_add_to_queue"} = $dbh->prepare(
"INSERT INTO messagequeue (msgid,fspath,recipient,queuename,system_id,person_id,creationtime) VALUES (?,?,?,?,?,?,?)"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_add_to_eventlog"} = $dbh->prepare(
"INSERT INTO eventlog (system_id,person_id,event,eventtime) VALUES (?,?,?,?)"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_message_count"} = $dbh->prepare(
"SELECT count(*) from messagequeue where system_id=? and person_id=? and creationtime > ( ? - 300 )"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_park_delayqueue"} = $dbh->prepare(
"UPDATE messagequeue SET queuename='hold' where queuename='delay' and system_id=?"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_lookup_peer"} = $dbh->prepare(
"SELECT peer_id,owner FROM peer where username=? and domain=? and confirmed='true'"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_lookup_peer_new"} = $dbh->prepare(
"SELECT peer_id,owner FROM peer where username=? and domain=? and owner=? and confirmed='false'"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_add_recipient"} = $dbh->prepare(
"INSERT INTO peer (username,domain,owner,creationtime,confirmed) VALUES (?,?,?,?,'false')"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;
    $self->{"q_confirm_message"} = $dbh->prepare(
"UPDATE messagequeue SET queuename='forward' , person_id=? , creationtime=? where msgid=? and recipient=?"
    );
    $self->{"q_confirm_peer"} = $dbh->prepare(
"UPDATE peer SET owner=? , creationtime=?, confirmed='true' where username=? AND domain=?"
    );
    $self->{"h_list_persons"} = "unixname\tfullname";
    $self->{"q_list_persons"} =
      $dbh->prepare("SELECT unixname,name FROM person ORDER BY unixname");
    $self->{"h_list_all_events"} = "time\tevent";
    $self->{"q_list_all_events"} =
      $dbh->prepare("select eventtime,event from eventlog order by eventtime");
    $self->{"h_list_all_systems"} = "net\thost";
    $self->{"q_list_all_systems"} =
      $dbh->prepare("select net,ip from system order by net,ip");
    $self->{"h_list_all_compromized_systems"} = "net\thost";
    $self->{"q_list_all_compromized_systems"} = $dbh->prepare(
        "select net,ip from system where trojanized='true' order by net,ip");
    $self->{"h_list_lists"} = "listaddress";
    $self->{"q_list_lists"} = $dbh->prepare(
        "select username || '\@'|| domain from address where list='true'");
    $self->{"h_list_events_without_person"} = "time\tevent";
    $self->{"q_list_events_without_person"} = $dbh->prepare(
"select eventtime,event from eventlog where person_id=0 order by eventtime"
    );
    $self->{"h_list_systems_promisq"} = "net\thost";
    $self->{"q_list_systems_promisq"} = $dbh->prepare(
        "select net,ip from system where promesq='true' order by net,ip");
    $self->{"h_list_persons_roaming"} = "unixname\tfullname";
    $self->{"q_list_persons_roaming"} = $dbh->prepare(
"SELECT unixname,name FROM person where roaming='true' ORDER BY unixname"
    );
    $self->{"h_list_events_without_system"} = "time\tevent";
    $self->{"q_list_events_without_system"} = $dbh->prepare(
"select eventtime,event from eventlog where system_id=0 order by eventtime"
    );
    $self->{"h_list_adresses_user"} = "address";
    $self->{"q_list_adresses_user"} = $dbh->prepare(
"select username || '\@'|| domain from address,addressuser,person where list='false' and addressuser.person_id=person.person_id and addressuser.address_id=address.address_id and unixname=?"
    );
    $self->{"h_list_events_for_system"} = "time\tevent";
    $self->{"q_list_events_for_system"} = $dbh->prepare(
"select eventtime,event from eventlog,system where eventlog.system_id=system.system_id and net=? and ip=? order by eventtime"
    );
    $self->{"h_list_queue"} = "time\tsender\trecipient\tmsgid";
    $self->{"q_list_queue"} = $dbh->prepare(
"select creationtime,unixname,recipient,msgid from messagequeue,person where queuename=? and person.person_id=messagequeue.person_id;"
    );
    $self->{"h_list_events_for_person"} = "time\tevent";
    $self->{"q_list_events_for_person"} = $dbh->prepare(
"select eventtime,event from eventlog,person where eventlog.person_id=person.person_id and unixname=? order by eventtime"
    );
    $self->{"q_add_list_mail"} = $dbh->prepare(
"insert into addressuser (address_id,person_id) select address_id,person_id from address,person where username=? and domain=? and unixname=?"
    );
    $self->{"q_clear_system"} = $dbh->prepare(
        "update system set trojanized='false' where net=1 and ip=56");
    $self->{"q_create_list_address"} = $dbh->prepare(
"insert into address (username,domain,shared,list) VALUES (?,?,'false','true')"
    );
    $self->{"q_set_host_promisquous"} =
      $dbh->prepare("update system set promesq=? where net=? and ip=?");
    $self->{"q_set_person_roaming"} =
      $dbh->prepare("update person set roaming=? where unixname=?");
    $self->{"q_set_list_as_shared"} = $dbh->prepare(
        "update address set shared=? where username=? and domain=?");
    $self->{"q_remove_from_list"} = $dbh->prepare(
"delete from addressuser where person_id in (select person_id from person where unixname=?) and address_id in (select address_id from address where username=? and domain=?)"
    );
    $self->{"q_delete_from_queue"} =
      $dbh->prepare("delete from messagequeue where msgid=?");
    $self->{"q_move_to_other_queue"} =
      $dbh->prepare("update messagequeue set queuename=? where msgid=?");
    $self->{"q_new_person"} = $dbh->prepare(
        "insert into person (unixname,name,roaming) VALUES (?,?,'false');");
    $self->{"q_create_system"} = $dbh->prepare(
"insert into system (net,ip,promesq,trojanized) VALUES (?,?,'false','false')"
    );
    $self->{"q_list_users_for_system"} = $dbh->prepare(
"select unixname,name from person where person_id in (select person_id from systemuser,system where systemuser.system_id=system.system_id and net=? and ip=?)"
    );
    $self->{"h_list_users_for_system"} = "unixname\tfullname";
    $self->{"q_list_system_for_user"}  = $dbh->prepare(
"select net,ip from system where system_id in (select system_id from systemuser,person where person.person_id=systemuser.person_id and unixname=?)"
    );
    $self->{"h_list_system_for_user"} = "net\thost";
    $self->{"q_list_system_users"}    = $dbh->prepare(
"select unixname,net,ip from person,system,systemuser where person.person_id=systemuser.person_id and systemuser.system_id=system.system_id order by unixname,net,ip"
    );
    $self->{"h_list_system_users"}  = "user\tnet\thost";
    $self->{"q_add_new_systemuser"} = $dbh->prepare(
"insert into systemuser (system_id,person_id) select system_id,person_id from person,system where unixname=? and net=? and ip=? limit 1"
    );
    $self->{"q_delete_systemuser"} = $dbh->prepare(
"delete from systemuser where person_id in (select person_id from person where unixname=?) and system_id in (select system_id from system where net=? and ip=?) "
    );
}

#Execute a prepared 'select' query that is expected to return a single record.
sub selectquery {
    my ( $self, $psname, @attributes ) = @_;
    my $sth = $self->{"q_$psname"};
    unless ($sth) {
        die "q_$psname is no valid prepared statement name";
    }
    my $rv = $sth->execute(@attributes)
      or die "Cannot execute: " . $sth->errstr();
    my @rval = $sth->fetchrow_array;
    $sth->finish();
    return @rval;
}

#Execute a prepared query that doesn't return records.
sub basicquery {
    my ( $self, $psname, @attributes ) = @_;
    my $sth = $self->{"q_$psname"};
    unless ($sth) {
        die "q_$psname is no valid prepared statement name";
    }
    $sth->execute(@attributes) or die "Cannot execute: " . $sth->errstr();
    if ( $sth->err ) {
        my $err = $sth->err;
        log_warn("ERR: '$err'\n");
    }
    $sth->finish();
    my $dbh = $self->{"dbh"};
    $dbh->commit();
    return;
}

sub setTrojanized {
    my ( $self, $system_id ) = @_;
    $self->basicquery( "set_trojanized", $system_id );
    return;
}

sub addToEventLog {
    my ( $self, @attributes ) = @_;
    $self->basicquery( "add_to_eventlog", @attributes );
    return;
}

sub parkDelayQueue {
    my ( $self, $system_id ) = @_;
    $self->basicquery( "park_delayqueue", $system_id );
    return;
}

sub addToQueue {
    my ( $self, $id, $file, $recipientid, $queue, $system_id, $person_id ) = @_;
    my $time = time();
    $self->basicquery( "add_to_queue", $id, $file, $recipientid, $queue,
        $system_id, $person_id, time() );
    return;
}

sub lookupClient {
    my ( $self, $ip ) = @_;
    my $mainnet = $self->basenet();
    if ( $ip =~ /^$mainnet\.(\d+)\.(\d+)$/ ) {
        my $netnum  = $1;
        my $hostnum = $2;
        my ( $system_id, $promesq, $trojanized ) =
          $self->selectquery( "lookup_client", $netnum, $hostnum );
        unless ($system_id) { return undef; }
        if   ( $promesq ne "true" ) { $promesq = 0; }
        else                        { $promesq = 1; }
        if   ( $trojanized ne "true" ) { $trojanized = 0; }
        else                           { $trojanized = 1; }
        return new MailWallClient(
            db         => $self,
            ip         => $ip,
            id         => $system_id,
            promesq    => $promesq,
            trojanized => $trojanized,
            net        => $netnum,
            host       => $hostnum
        );
    }
    return undef;
}

sub lookupSender {
    my ( $self, $mail ) = @_;
    my ( $username, $domain ) = split( /\@/, $mail );
    $username =~ s/.*["<]//;
    $domain   =~ s/[">].*//;
    my ( $person_id, $roaming ) =
      $self->selectquery( "lookup_sender", $username, $domain );
    if ($person_id) {
        if   ( $roaming ne "true" ) { $roaming = 0; }
        else                        { $roaming = 1; }
        return new MailWallPerson(
            db       => $self,
            personid => $person_id,
            roaming  => $roaming,
            username => $username,
            domain   => $domain
        );
    }
    return undef;
}

sub lookupWsUser {
    my ( $self, $system_id, $person_id ) = @_;
    my @rval = $self->selectquery( "lookup_wsuser", $system_id, $person_id );
    return $rval[0];
}

sub messageCount {
    my ( $self, $system_id, $person_id, $time ) = @_;
    my @rval =
      $self->selectquery( "message_count", $system_id, $person_id, $time );
    if (@rval) {
        return $rval[0];
    }
    return 0;
}

sub createBasicEventLog {
    my ( $self, $peerip ) = @_;
    return new MailWallEventLog( db => $self, clientip => $peerip );
}

sub newMailWallRecipient {
    my ( $self, $mail, $defaultowner ) = @_;
    my ( $username, $domain ) = split( /\@/, $mail );
    $username =~ s/.*["<]//;
    $domain   =~ s/[">].*//;
    my $recipientinfo = "undefined";
    my $ownerinfo     = 0;
    my $peer_id       = 0;
    my $owner         = 0;
    my ( $person_id, $roaming ) =
      $self->selectquery( "lookup_sender", $username, $domain );

    if ($person_id) {
        $recipientinfo = "local";
    }
    else {
        ( $peer_id, $owner ) =
          $self->selectquery( "lookup_peer", $username, $domain );
        if ($peer_id) {
            $recipientinfo = "remote";
            $ownerinfo     = $owner;
        }
        else {
            $owner = $defaultowner;
            ( $peer_id, $owner ) =
              $self->selectquery( "lookup_peer_new", $username, $domain,
                $defaultowner );
            unless ($peer_id) {
                $self->basicquery( "add_recipient", $username, $domain,
                    $defaultowner, time() );
                ( $peer_id, $owner ) =
                  $self->selectquery( "lookup_peer_new", $username, $domain,
                    $defaultowner );
            }
            $recipientinfo = "undefined";
            $ownerinfo     = $owner;
        }
    }
    return new MailWallPeer(
        user      => $username,
        domain    => $domain,
        rcptwhere => $recipientinfo,
        owner     => $ownerinfo,
        id        => $peer_id
    );
}

sub adminOk {
    my ( $self, $client, $sender, $processingmode ) = @_;
    if ( $processingmode eq "queue" ) {
        return 1;
    }
    elsif ( $processingmode eq "peers" ) {
        return 1;
    }
    elsif ( $processingmode eq "admin" ) {
        my @adminiplist = split( /,/, $self->adminip() );
        my $hasadminip = 0;
        foreach my $adminip (@adminiplist) {
            if ( $client->getIp() eq $adminip ) {
                $hasadminip = 1;
            }
        }
        unless ($hasadminip) {
            log_warn( "IP "
                  . $client->getIp()
                  . " not in adminip set:'"
                  . $self->adminip()
                  . "'" );
            return 0;
        }
        my @adminuserlist = split( /,/, $self->adminuser() );
        my $isadminuser = 0;
        foreach my $adminuser (@adminuserlist) {
            if ( $sender->getUserName() eq $adminuser ) {
                $isadminuser = 1;
            }
        }
        unless ($isadminuser) {
            log_warn( "USER "
                  . $sender->getUserName()
                  . " not in adminset:'"
                  . $self->adminuser()
                  . "'" );
        }
        return $isadminuser;
    }
    else {
        return 0;
    }
}

#Move a message to the forward queue.
sub confirmMessage {
    my ( $self, $msgid, $recipient, $sender ) = @_;
    my $time = time();
    $self->basicquery( "confirm_message", $sender->getId(), $time, $msgid,
        $recipient );
    return;
}

#Mark a peer (recipient) as being available for auto delay only traversal of normal messages.
sub addPermittedRecipient {
    my ( $self, $recipient, $sender ) = @_;
    my $time = time();
    my ( $username, $domain ) = split( /\@/, $recipient );
    $self->basicquery( "confirm_peer", $sender->getId(), $time, $username,
        $domain );
    return 0;
}

#The generic part of admin command processing for commands that return a list of things.
sub adminListCommand {
    my ( $self, $commandname, @attributes ) = @_;
    my $sth = $self->{"q_$commandname"};
    unless ($sth) {
        log_warn("Command not implemented $commandname\n");
        return "Command not implemented";
    }
    unless ( $sth->execute(@attributes) ) {
        log_warn( "Command execution resulted in an error : $commandname : "
              . $sth->errstr()
              . "\n" );
        return "Problem executing SQL command: " . $sth->errstr();
    }
    my $rval = "\n\n";
    if ( $self->{"h_$commandname"} ) {
        $rval = $self->{"h_$commandname"} . "\n\n";
    }
    my $count = 0;
    while ( my @values = $sth->fetchrow_array() ) {
        foreach my $index ( 0 .. $#values ) {
            $rval .= $values[$index];
            if ( $index < $#values ) {
                $rval .= "\t";
            }
        }
        $rval .= "\n";
        $count++;
    }
    $sth->finish();
    if ( $count == 0 ) {
        $rval = "Query returned an empty set.";
    }
    return $rval;
}

#The generic part of admin command processing for commands that update stuff and dont return data.
sub adminUpdateCommand {
    my ( $self, $commandname, @attributes ) = @_;
    if ( $commandname eq "add_new_mail" ) {
        return "Command not yet implemented";
    }
    else {
        my $sth = $self->{"q_$commandname"};
        unless ($sth) {
            log_warn("Command not implemented : $commandname\n");
            return "Command not implemented";
        }
        unless ( $sth->execute(@attributes) ) {
            log_warn( "Command execution resulted in an error : $commandname : "
                  . $sth->errstr()
                  . "\n" );
            return "Problem executing SQL command: " . $sth->errstr();
        }
        $sth->finish();
        my $dbh = $self->{"dbh"};
        $dbh->commit();
        return "Update completed without errors";
    }
}

#FIXME
sub invokeBatch {
    my ( $self, $reportname, $whaton, $attribute ) = @_;
    my $batchfile = "/opt/mailwall/batch/${whaton}/${reportname}.pl";
    if ( -f $batchfile ) {
        my $ATTRIBUTE = $attribute;
        my $DB        = $self->{"dbh"};
        my $RESULT    = "";
        unless ( open( BATCH, $batchfile ) ) {
            return "ACL problem executing batch '$reportname' for '$whaton'.";
        }
        my $batch = "";
        while (<BATCH>) {
            $batch .= $_;
        }
        close(BATCH);
        eval($batch);
        if ($@) {
            return
              "Error while running  batch '$reportname' for '$whaton' : $@.";
        }
        if ($RESULT) {
            return $RESULT;
        }
        return "Empty result from batch '$reportname' for '$whaton'.";
    }
    else {
        return "No batch '$reportname' defined for '$whaton'.";
    }
}

sub processUpdateForm {
    my ( $self, $whatoff, $data ) = @_;
    unless ($data) {
      return "Unable to process updateform with empty data reference\n";
    }
    my $batchfile = "/opt/mailwall/batch/${whatoff}/update.pl";
    if ( -f $batchfile ) {
        my $DB     = $self->{"dbh"};
        my $DATA   = $data;
        unless ($DATA) {
           return "Data disapeared in processUpdateForm\n";
        }
        my $RESULT = "";
        unless ( open( BATCH, $batchfile ) ) {
            return "ACL problem executing batch 'update' for '$whatoff'.";
        }
        my $batch = "";
        while (<BATCH>) {
            $batch .= $_;
        }
        close(BATCH);
        unless ($DATA) {
           return "Data disapeared in processUpdateForm (2) \n";
        }
        eval($batch);
        if ($@) {
            return "Error while running  batch 'update' for '$whatoff' : $@.";
        }
        if ($RESULT) {
            return $RESULT;
        }
        return "Empty result from batch 'update' for '$whatoff'.";
    }
    else {
        return "No batch 'update' defined for '$whatoff'. ($batchfile does not exist as file) \n";
    }
}

no Moose;
__PACKAGE__->meta->make_immutable;
