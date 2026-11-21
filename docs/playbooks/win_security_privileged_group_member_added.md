# Playbook: Member Added To A Privileged Windows Group

**Rule:** `win_security_privileged_group_member_added` · **ATT&CK:** T1098 Account Manipulation · **Severity:** High

## What it means

An account was added to a highly privileged group (Domain Admins, Enterprise Admins, Schema Admins, local Administrators, Account Operators or Backup Operators). Attackers do this to keep admin rights after they first get in. Membership of these groups should change rarely and only through approved requests.

## Triage

1. **Who was added, by whom, to what?** `MemberName` (added), `SubjectUserName` (who did it), `TargetUserName` and `TargetSid` (the group), `Computer` (DC or workstation).
2. **Is there an approved request?** Check the change or access ticket.
3. **Does it make sense?** Is the added account a person who needs admin, or a service, contractor or brand new account?
4. **Is the actor's session normal?** Check the actor's recent logons (4624): time, source host and logon type. An admin change made from an unusual workstation or at an unusual hour is a red flag.
5. **What did the new member do next?** Search their logons and actions after the change (new services, remote logons to servers, more group changes).

## Escalate to L2 when

- There is no ticket, or the actor is not on the approved admin list
- The added account is new, disabled until recently, a service account, or external
- Domain Admins, Enterprise Admins or Schema Admins were changed (escalate these immediately)

## Close as benign when

- A matching approved ticket exists and the actor, member, group and time all match it

## Response actions (with L2 approval)

- Remove the account from the group
- Disable the added account and reset the actor's credentials if either is suspected compromised
- Review all privileged group changes in the last 30 days
