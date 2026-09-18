# AD-AttributeEditor5
AD Attribute Editor 5

Please stop by https://m365admintools.com/ad-attribute-editor for more info and IT engineering tools.
A forest-aware bulk attribute editor for Active Directory, with a mandatory what-if preview before anything is written.

Pick a domain, an object class, an attribute, an action, and a scope. Run what-if and every matched object is listed with its current value, the proposed value, and whether it would actually change. Review it, export it, then apply. Live mode stays locked until a what-if plan exists, and the plan is discarded the moment any input changes.

Uses `System.DirectoryServices` directly. No RSAT and no ActiveDirectory module required.

<img width="959" height="813" alt="image" src="https://github.com/user-attachments/assets/364e14ae-345c-4f45-b2c0-bd99df1542c7" />


## Why this exists

ADUC's attribute editor handles one object at a time. PowerShell one-liners handle bulk changes but give no preview, and a mistyped filter against `Set-ADUser` can rewrite an attribute across a domain in seconds with no record of the previous values.

This tool sits between the two. Every run produces a plan first, the plan lists old and new values per object, and both the plan and the applied changes are written to an audit log with the account that ran them.

It is the successor to AD Attribute Editor 4.0, originally written in WinBatch in 2009 and rebuilt in PowerShell.

## Requirements

| Item | Requirement |
|---|---|
| PowerShell | Windows PowerShell 5.1 on Windows |
| Modules | None. No RSAT, no ActiveDirectory module |
| Network | LDAP access to a domain controller in the target forest |
| Rights | Read access for what-if. Write permission on the target attribute for live mode |

## Quick start

```powershell
# Bind using the current user's domain
.\AD-AttributeEditor5.ps1

# Bind to a specific domain controller or DNS domain
.\AD-AttributeEditor5.ps1 -Server dc01.corp.contoso.com
```

If the script is blocked on first run:

```powershell
Unblock-File .\AD-AttributeEditor5.ps1
```

## Workflow

1. **Connect.** The tool resolves the forest root and enumerates every domain partition by reading the crossRef objects in the configuration partition, so child domains appear without any extra configuration. Alternate credentials are supported.
2. **Pick the domain.** Forest root or any child.
3. **Pick the object class.** User, Group, Organizational Unit, Computer, or Contact.
4. **Pick the attribute.** Read from that class's schema, so the list reflects your schema including any extensions.
5. **Pick the action.** Set, Clear, Add value, Remove value, or Set if empty.
6. **Pick the scope.** See the table below.
7. **Run what-if.** Nothing is written.
8. **Review, then apply.**

## Scopes

| Scope | Notes |
|---|---|
| Single object | Loaded from a dropdown of objects in the domain |
| List from file | One name per line. With "value per line" ticked, each line is `name<space>value`, so every object can receive a different value |
| Container | An OU or container, with an optional subtree switch |
| Group members | Members of a selected group, optionally including nested membership. Members are matched against the object class chosen in step 3 |
| Entire domain | Every matching object in the domain. What-if is mandatory and a typed confirmation is required |

## Safety model

This tool writes to Active Directory. These are the controls that sit between the operator and a bad change.

- **What-if is mandatory.** The apply button is disabled until a plan exists.
- **The plan expires on any input change.** Changing the attribute, action, value, or scope invalidates the plan, so you cannot review one thing and apply another.
- **Read-only attributes are hard blocked.** Operational and system-maintained attributes, such as object identifiers, timestamps, logon counters, and the security descriptor, cannot be selected for writing at all.
- **High-impact attributes require a typed confirmation.** Attributes that change identity, authentication, group membership, or naming carry a second gate that requires typing the exact object count before the change runs. The same gate applies to any domain-wide scope, and to any change affecting 50 or more objects.
- **The confirmation dialog shows a sample.** Domain, class, attribute, action, scope, object count, and the first five old-to-new value pairs.
- **Everything is logged.** Both what-if runs and applied changes are appended to the log file with a timestamp, the object name and distinguished name, the attribute, action, old value, new value, status, and the account that ran it.
- **Failures are per object.** A write that fails is recorded as an error against that row and the run continues.

None of this makes a wrong plan safe. It makes a wrong plan visible before it is applied, which is the point.

## Value tokens

The new value can reference other attributes on the same object using `%attributeName%`. The token is resolved per object at the moment the value is written.

```
%sAMAccountName%@contoso.com
%givenName%.%sn%
```

Unknown tokens resolve to an empty string, so check the what-if plan before applying anything that uses them.

## Output

- **Plan grid** showing name, distinguished name, current value, proposed value, effect, and status per object.
- **Export CSV** of the plan, for review, for a change record, or for a colleague to check before the change runs.
- **Audit log** at the path set in the window. What-if entries are marked `WHATIF` and applied changes `CHANGE`, so a single log file records both what was considered and what was done.

## Limitations

- **No undo.** The audit log records previous values, which makes a manual reversal possible, but there is no rollback button. Export the plan and keep the log before applying anything wide.
- **No AD Recycle Bin interaction.** This tool edits attributes on live objects. It does not restore or resurrect anything.
- Single-valued and multi-valued attributes behave differently under Add and Remove. Confirm the effect column in the what-if plan rather than assuming.
- The interface is WinForms, so Windows only, and Windows PowerShell 5.1 rather than PowerShell 7.
- Changes are written to the domain controller bound at connect time, so allow for replication before verifying elsewhere.

## Related

- Free Microsoft 365, Active Directory, and Veeam tools at [m365admintools.com](https://m365admintools.com)

## Author

Charles Arconi, [m365admintools.com](https://m365admintools.com)

## License

MIT. See [LICENSE](LICENSE).
