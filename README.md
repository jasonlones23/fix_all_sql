# Fix All Sql

Fix All Sql is a REDCap External Module designed to help administrators identify, review, and correct discrepancies discovered through analysis of fields using the Dynamic Query (SQL) field type.

The module was created to reduce the amount of manual investigation and repetitive correction work often required when Dynamic Query (SQL) data are found to be inconsistent with expected values.

Rather than simply reporting discrepancies, Fix All Sql provides a workflow for reviewing findings, narrowing the scope of analysis, and applying corrections in a controlled manner.

## Features

### Administrative Review

Fix All Sql is designed around the assumption that administrators should be able to review findings before making changes.

Detection and remediation are intentionally separate steps.

### Discrepancy Detection

Fix All SQL checks Dynamic Query (SQL) fields for discrepancies and allows for review of issues which require attention.

- Discrepancy Scan Limit 

This feature stops the discovery process after a declared number of discrepancies are found. This helps limit processing time for potentially large scans.

### Scoping

Using filter, discrepancies can be narrowed to specific:

- Instruments
- Fields
- Records
- Events

This allows administrators to focus on a manageable subset of findings.

### Selection Mode 

Users can utilize Selection Mode to pre-select results.

### Selective Fixes

After findings have been reviewed, Fix All Sql provides a controlled process for applying corrections.

By default, all identified discrepancies are selected for remediation.

Administrators can review findings and choose to:

- Apply remediation to all findings
- Select specific records or discrepancies for correction
- Exclude findings that do not require action

This allows remediation efforts to begin broadly while still providing fine-grained control when administrative review identifies exceptions or edge cases.

The goals of remediation are to:

- Reduce repetitive manual work
- Standardize correction workflows
- Support targeted fixes
- Minimize unintended changes

## Typical Use Cases

### Bulk Correction

Apply the same corrective action across multiple discrepancies without requiring record-by-record updates.

### SQL Field Change/Addition 

Identify how a change to, or addition of, a Dynamic Query (SQL) field affects previously collected data.

### Post-Migration Validation

Review Dynamic Query (SQL) fields in projects following upgrades, imports, or other large administrative changes.

## Limitations

Fix All Sql is limited by the SQL used in the Dynamic Query (SQL) fields themselves.

The module does not attempt to determine issues with the SQL used in the Dynamic Query (SQL) fields. Instead, it provides a framework for detecting and remediating issues where saved data do not align with current Dynamic Query (SQL) query results.

As a result:

- A discrepancy may exist that is not detected by the current queries.
- A reported discrepancy may not represent a true issue.
- Institution-specific customizations may require additional queries.
- Administrative review is required before fixes are applied.

Fix All Sql should be viewed as a decision-support and remediation tool rather than an automated data repair system.

The final determination of whether a discrepancy exists, and whether remediation is appropriate, remains the responsibility of the administrator.

## Requirements

- Administrative access to review findings
- Appropriate permissions to perform remediation activities

## Installation

1. Download or clone the repository.
2. Copy the module into your REDCap External Modules directory.
3. Enable the module through the External Modules manager.
4. Configure settings as needed for your environment.

## Recommended Practices

- Review findings before applying fixes.
- Start with a limited scope when testing large-scale corrections.
- Validate results after fix activities are complete.

## Settings Defaults

The module includes layered safeguards where built-in hard caps remain in code,
and settings can provide defaults or stricter limits.

- Project setting `selection_mode` default: `keep_if_valid`
- Project setting `default_discrepancy_limit` default: `1000`
- System setting `max_records_threshold` default: `0` (disabled)
- System setting `max_record_range_size` default: `0` (use built-in max - 10000)
- System setting `max_discrepancy_limit` default: `0` (use built-in max - 5000)

When a stricter system cap is provided (value > 0), it is enforced.
When a system cap is set to `0`, the module uses its built-in hard maximum.

## Support

Bug reports, feature requests, and questions should be submitted through the project's GitHub Issues page.

## Disclaimer

Fix All Sql is intended for use by REDCap administrators and other individuals familiar with REDCap data structures, metadata, and administrative workflows.

Administrators should review findings, understand the impact of proposed changes, and validate results before performing remediation in production environments.

Development of this module included the use of Microsoft Copilot as an AI-assisted development tool. All AI-generated contributions were reviewed, modified as necessary, tested, and validated by the author prior to inclusion in the project.

## License

See the LICENSE file for licensing information.

# Changelog

## Version 1.0.0

Initial public release.

### Features

- Project, event, instrument, field, and record scoping
- Selective remediation of identified findings
- Bulk remediation workflows
- Administrative review prior to remediation
- Discrepancy limits and performance safeguards

### Notes

- Findings are selected for remediation by default.
- Administrators may individually include or exclude findings before remediation is performed.
- The accuracy of discrepancy detection depends on the underlying Dynamic Query (SQL) field that defines each query.

