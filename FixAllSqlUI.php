<?php
namespace OSUCOMRIT\FixAllSql;

global $module, $project_id;
/** @var FixAllSql $module, $project_id */

if (empty($_SESSION['fixallsql_csrf'])) {
    $_SESSION['fixallsql_csrf'] = bin2hex(random_bytes(32));
}

$action = $_POST["action"] ?? null;
$allowedActions = ["discover", "fix"];
$result = null;
$error = null;

$defaultDiscrepancyLimit = $module->getDefaultDiscrepancyLimit();

$displayLimit = (int) ($_POST["discrepancy_limit"] ?? $defaultDiscrepancyLimit);
if ($displayLimit <= 0) {
    $displayLimit = $defaultDiscrepancyLimit;
}

//HTML escape helper:
$h = function ($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, "UTF-8");
};

//Selected helper:
$selected = function ($current, $value) {
    return (string) $current === (string) $value ? "selected" : "";
};

//Checked helper:
$checked = function ($value) {
    return !empty($value) ? "checked" : "";
};

//Defaults from project settings:
$defaults = [
    "selection_mode" => $module->getDefaultSelectionMode(),
];

$selectionModeDetails = $module->getSelectionModeDetails();

//Form values:
$form = [
    "scope_fields" => isset($_POST["scope_fields"])
        ? (array) $_POST["scope_fields"]
        : [],
    "scope_instruments" => isset($_POST["scope_instruments"])
        ? (array) $_POST["scope_instruments"]
        : [],
    "scope_events" => isset($_POST["scope_events"])
        ? (array) $_POST["scope_events"]
        : [],
    "specific_records_text" => $_POST["specific_records_text"] ?? "",
    "selection_mode" =>
        $_POST["selection_mode"] ??
        ($defaults["selection_mode"] ?: FixAllSql::DEFAULT_SELECTION_MODE),
    "confirm_live_run" => isset($_POST["confirm_live_run"]) ? 1 : 0,
    "discrepancy_limit" => isset($_POST["discrepancy_limit"])
        ? (int) $_POST["discrepancy_limit"]
        : $defaultDiscrepancyLimit,
];

//Runtime overrides passed to the module
$overrides = [
    "scope_fields" => $form["scope_fields"],
    "scope_instruments" => $form["scope_instruments"],
    "scope_events" => $form["scope_events"],
    "specific_records_text" => (string) ($form["specific_records_text"] ?? ""),
    "selection_mode" => trim((string) $form["selection_mode"]),
    "simulate_only" => 0,
    "discrepancy_limit" => (int) ($form["discrepancy_limit"] ?? $defaultDiscrepancyLimit),
    "selected_items" => [],
];

//Map only known, user-correctable failures to friendly messages.
//Everything else gets a generic message.
$userMessageByException = [
    "Invalid action." =>
        "Invalid action requested. Refresh the page and try again.",
    "Too many selected discrepancies were submitted." =>
        "Too many selected discrepancies were submitted. Re-run discovery and retry with fewer selections.",
    "Invalid security token." =>
        "Your session token is invalid or expired. Refresh the page and try again.",
    "No discrepancies were selected for remediation." =>
        "Select at least one discrepancy before running a fix.",
    "Selected finding is no longer valid. Re-run discovery and try again." =>
        "Selected rows are out of date. Run discovery again, then retry.",
    "Live fix requires confirmation. Check the confirmation box and try again." =>
        "Confirm the live fix option before running remediation.",
    "Discrepancy scan limit must be at least 1." =>
        "Discrepancy scan limit must be at least 1.",
];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    try {
        // Reject unknown operations explicitly.
        if (!in_array((string) $action, $allowedActions, true)) {
            throw new \Exception("Invalid action.");
        }

        $csrfToken = $_POST["csrf_token"] ?? "";

        // Validate anti-CSRF token before handling any action payload.
        if (
            empty($_SESSION["fixallsql_csrf"]) ||
            !hash_equals($_SESSION["fixallsql_csrf"], $csrfToken)
        ) {
            throw new \Exception("Invalid security token.");
        }

        if ($action === "discover") {
            $result = $module->discover(
                $project_id,
                array_merge($form, $overrides)
            );
        } elseif ($action === "fix") {
            if (empty($_POST["confirm_live_run"])) {
                throw new \Exception(
                    "Live fix requires confirmation. Check the confirmation box and try again."
                );
            }

            // Treat client-submitted selections as untrusted and bounded.
            $maxPostedSelections = min(
                max((int) ($form["discrepancy_limit"] ?? 1000), 1),
                $module->getMaxDiscrepancyLimit()
            );

            $postedSelectedRecords = $_POST["selected_records"] ?? [];
            if (!is_array($postedSelectedRecords)) {
                $postedSelectedRecords = [];
            }

            $postedSelectedRecords = array_slice(
                $postedSelectedRecords,
                0,
                $maxPostedSelections + 1
            );

            if (count($postedSelectedRecords) > $maxPostedSelections) {
                throw new \Exception(
                    "Too many selected discrepancies were submitted."
                );
            }

            $selected_items = [];
            foreach ($postedSelectedRecords as $json) {
                $decoded = json_decode($json, true);
                if (is_array($decoded)) {
                    $selected_items[] = $decoded;
                }
            }

            $overrides["selected_items"] = $selected_items;

            $result = $module->fix($project_id, $overrides);
        }

    } catch (\Throwable $e) {
        $errorRef = substr(sha1(uniqid("fixallsql", true)), 0, 10);
        $message = (string) $e->getMessage();

        error_log(
            "[FixAllSql] ref={$errorRef} pid={$project_id} user=" . USERID .
            " action=" . ($action ?? "") .
            " error=" . $message
        );

        $error =
            $userMessageByException[$message] ??
            "The request could not be completed. Contact an administrator with reference {$errorRef}.";
    }
}
?>
<style>
    .fixallsql-wrap {
        max-width: 1400px;
    }

    .fixallsql-grid {
        display: grid;
        grid-template-columns: repeat(12, minmax(0, 1fr));
        gap: 12px;
        margin-bottom: 18px;
    }

    .fixallsql-card {
        background: #fff;
        border: 1px solid #d9d9d9;
        border-radius: 8px;
        padding: 14px 16px;
        margin-bottom: 16px;
    }

    .fixallsql-title {
        margin-top: 0;
        margin-bottom: 6px;
    }

    .fixallsql-subtitle {
        margin-top: 0;
        margin-bottom: 0;
        color: #555;
    }

    .fixallsql-field {
        grid-column: span 12;
    }

    .fixallsql-field.half {
        grid-column: span 6;
    }

    .fixallsql-field.third {
        grid-column: span 4;
    }

    .fixallsql-field.quarter {
        grid-column: span 3;
    }

    .fixallsql-field label {
        display: block;
        font-weight: 600;
        margin-bottom: 5px;
    }

    .fixallsql-field input[type="text"],
    .fixallsql-field input[type="number"],
    .fixallsql-field select {
        width: 100%;
        height: 38px;
        padding: 6px 10px;
        border: 1px solid #bbb;
        border-radius: 4px;
        background: #fff;
        box-sizing: border-box;
    }

    .fixallsql-help {
        display: block;
        margin-top: 5px;
        color: #333;
        font-size: 12px;
    }

    .fixallsql-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        align-items: center;
        margin-top: 12px;
    }

    .fixallsql-alert {
        padding: 12px 14px;
        border-radius: 6px;
        margin-bottom: 16px;
    }

    .fixallsql-alert-error {
        background: #fdeaea;
        border: 1px solid #e2a8a8;
        color: #8a1f1f;
    }

    .fixallsql-alert-info {
        background: #eef5ff;
        border: 1px solid #b8d1f3;
        color: #204d7a;
    }

    .fixallsql-summary {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin: 12px 0 16px 0;
    }

    .fixallsql-badge {
        display: inline-block;
        padding: 8px 12px;
        border-radius: 999px;
        background: #f0f0f0;
        font-weight: 600;
    }

    .fixallsql-badge-secondary { background: #e9ecef; }
    .fixallsql-badge-success   { background: #d7f0dc; color: #1f6b2c; }
    .fixallsql-badge-warning   { background: #fff0cc; color: #8a6300; }
    .fixallsql-badge-danger    { background: #f8d7da; color: #842029; }
    .fixallsql-badge-info      { background: #dbeafe; color: #1d4f91; }

    .fixallsql-table-wrap {
        overflow-x: auto;
    }

    .fixallsql-table {
        width: 100%;
        border-collapse: collapse;
        background: #fff;
    }

    .fixallsql-table th,
    .fixallsql-table td {
        border: 1px solid #ddd;
        padding: 8px 10px;
        vertical-align: top;
        text-align: left;
    }

    .fixallsql-table th {
        background: #f5f5f5;
        font-weight: 700;
    }

    .fixallsql-status-fixed      { color: #1f6b2c; font-weight: 700; }
    .fixallsql-status-error      { color: #8a1f1f; font-weight: 700; }
    .fixallsql-status-manual     { color: #a66b00; font-weight: 700; }
    .fixallsql-status-locked     { color: #6b5b00; font-weight: 700; }
    .fixallsql-status-unchanged  { color: #555; font-weight: 700; }
    .fixallsql-status-unresolved { color: #7a2ea8; font-weight: 700; }

    .fixallsql-muted {
        color: #666;
    }

    @media (max-width: 900px) {
        .fixallsql-field.half,
        .fixallsql-field.third,
        .fixallsql-field.quarter {
            grid-column: span 12;
        }
    }

    .fixallsql-field select[multiple] {
        min-height: 140px;
    }
    
    .fixallsql-limit-note {
        margin-bottom: 10px;
        color: #555;
        font-size: 13px;
    }

    .select2-container--default .select2-selection--multiple {
        min-height: 38px;
        height: 38px;
        padding: 6px 6px;
        border: 1px solid #bbb;
        border-radius: 4px;
        background: #fff;
    }

    .select2-container--default .select2-selection__rendered {
        line-height: normal;
        padding-top: 2px;
    }

    .select2-container--default .select2-selection__choice {
        margin-top: 2px;
    }

    .select2-container--default .select2-selection--single {
        height: 38px;
    }
</style>

<?php
$sqlFields = $module->sqlFields($project_id, []);
if (
    !empty($form["scope_instruments"]) &&
    is_array($form["scope_instruments"])
) {
    $sqlFields = array_values(
        array_filter($sqlFields, function ($sf) use ($form) {
            return in_array($sf["form"], $form["scope_instruments"], true);
        })
    );
}
?>

<div class="fixallsql-wrap">
    <h3 class="fixallsql-title"><strong>Fix All SQL</strong></h3>
    <p class="fixallsql-subtitle">
        Project-wide discovery and fix for Dynamic Query (SQL) fields, modeled after Data Quality Rule H.
        <strong>Use with caution.</strong><br>
    </p>

    <?php if ($error): ?>
        <div class="fixallsql-alert fixallsql-alert-error">
            <strong>Error:</strong> <?= $h($error) ?>
        </div>
    <?php endif; ?>
    <br>
    <div class="fixallsql-card">
        <form method="post">       
            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars($_SESSION['fixallsql_csrf'], ENT_QUOTES) ?>"
            >
            <div class="fixallsql-grid">
                <div class="fixallsql-field half">
                    <label for="scope_instruments">Instrument Selector</label>
                    <?php
                    $selectedInstruments = $form["scope_instruments"] ?? [];
                    $selectedInstruments = is_array($selectedInstruments)
                        ? $selectedInstruments
                        : [];
                    ?>
                    <select id="scope_instruments" name="scope_instruments[]" multiple="multiple" style="width:100%;">
                        <?php foreach (
                            \REDCap::getInstrumentNames()
                            as $formName => $label
                        ): ?>
                            <option value="<?php echo htmlspecialchars(
                                $formName
                            ); ?>"
                                <?php echo in_array(
                                    $formName,
                                    $selectedInstruments
                                )
                                    ? "selected"
                                    : ""; ?>>
                                <?php echo htmlspecialchars($formName); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <span class="fixallsql-help">
                        Optional. Select instruments. Leave blank for no limit.
                    </span>
                </div>

                <div class="fixallsql-field half">
                    <label for="scope_fields">Field Selector</label>
                    <?php $selectedFields = $form["scope_fields"] ?? []; ?>
                    <select id="scope_fields" name="scope_fields[]" multiple="multiple" style="width:100%;">
                        <?php foreach ($sqlFields as $sf): ?>
                            <?php
                            $field = $sf["field"];
                            $label =
                                $Proj->metadata[$field]["element_label"] ?? "";
                            ?>
                            <option 
                                value="<?php echo htmlspecialchars($field); ?>"
                                data-form="<?php echo htmlspecialchars(
                                    $sf["form"]
                                ); ?>"
                                <?php echo in_array($field, $selectedFields)
                                    ? "selected"
                                    : ""; ?>>
                                <?php echo htmlspecialchars($field); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <span class="fixallsql-help">
                        Optional. Select individual SQL fields. Leave blank for all fields.
                    </span>
                </div>

                <div class="fixallsql-field half">
                    <label for="specific_records">Record Selector</label>                
                    <?php
                    $selectedRecords = $form["specific_records"] ?? [];
                    $selectedRecords = is_array($selectedRecords)
                        ? $selectedRecords
                        : [];
                    ?>
                        <input
                            type="text"
                            id="specific_records"
                            name="specific_records_text"
                            value="<?php echo htmlspecialchars(
                                (string) ($form["specific_records_text"] ?? "")
                            ); ?>"
                            style="width:100%;"
                            placeholder="e.g. 1001,1002,1003 or 1001-1010"
                        >
                    <span class="fixallsql-help">
                        Optional. Enter record IDs separated by commas. Ranges can be used.
                    </span>
                </div>

                <div class="fixallsql-field half">
                    <label for="scope_events">Events Selector</label>
                    <?php
                    $selectedEvents = $form["scope_events"] ?? [];
                    $selectedEvents = is_array($selectedEvents)
                        ? $selectedEvents
                        : [];
                    ?>
                    <select id="scope_events" name="scope_events[]" multiple="multiple" style="width:100%;">
                        <?php foreach (
                            \REDCap::getEventNames(true)
                            as $event_id => $eventName
                        ): ?>
                            <?php
                            $eventForms = $Proj->eventsForms[$event_id] ?? [];
                            $formsCsv = implode(",", array_values($eventForms));
                            ?>
                            <option
                                value="<?php echo htmlspecialchars(
                                    $event_id
                                ); ?>"
                                data-forms="<?php echo htmlspecialchars(
                                    $formsCsv
                                ); ?>"
                                <?php echo in_array(
                                    (string) $event_id,
                                    array_map("strval", $selectedEvents),
                                    true
                                )
                                    ? "selected"
                                    : ""; ?>
                            >
                                <?php echo htmlspecialchars($eventName); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>

                    <span class="fixallsql-help">
                        Optional. Select events. Leave blank for no limit.
                    </span>
                </div>

                <div class="fixallsql-field half">
                    <label for="discrepancy_limit">Discrepancy Scan Limit</label>
                    <input
                        type="number"
                        id="discrepancy_limit"
                        name="discrepancy_limit"
                        value="<?= $h(
                            $_POST["discrepancy_limit"] ??
                                $defaultDiscrepancyLimit
                        ) ?>"
                        min="1"
                    >                    
                    <span class="fixallsql-help">
                        Maximum discrepancies to process before stopping. Large values may impact performance.<br>
                        Overall results may be incomplete. Limits - Default: <?= $h(
                            $defaultDiscrepancyLimit
                        ) ?>. Max: <?= $h(
                            $module->getMaxDiscrepancyLimit()
                        ) ?>.
                    </span>
                </div>

                <div class="fixallsql-field half">
                    <label for="selection_mode">Selection Mode</label>
                    <select id="selection_mode" name="selection_mode">
                        <?php foreach ($selectionModeDetails as $modeValue => $modeMeta): ?>
                            <option value="<?= $h($modeValue) ?>" <?= $selected(
                                is_array($form)
                                    ? $form["selection_mode"] ?? ""
                                    : "",
                                $modeValue
                            ) ?>><?= $h($modeMeta["label"] ?? $modeValue) ?></option>
                        <?php endforeach; ?>
                    </select>
                    <span class="fixallsql-help">
                        Used when SQL returns multiple possible values.
                    </span>
                </div>      
                
                <div class="fixallsql-field half">                    
                    <div class="fixallsql-actions">
                        <button type="submit" name="action" value="discover" class="btn btn-secondary">
                            Discover SQL Issues
                        </button>

                        <button type="submit" name="action" value="fix" class="btn btn-danger" id="fix-sql-btn" disabled>
                            Fix SQL Issues
                        </button>

                        <label style="font-weight:normal; margin:0 6px 0 12px;">
                            <input type="checkbox" name="confirm_live_run" value="1" <?= $checked(
                                is_array($form)
                                    ? $form["confirm_live_run"] ?? 0
                                    : 0
                            ) ?>>
                            I understand running 'Fix SQL Issues' will write data.
                        </label>
                    </div>
                </div>

                <div class="fixallsql-field half">
                    <span><strong>Selection Mode Key:</strong>
                        <ul style="margin:6px 0 0 18px; padding:0;">
                            <?php foreach ($selectionModeDetails as $modeMeta): ?>
                                <li><strong><?= $h($modeMeta["label"] ?? "") ?></strong> — <?= $h(
                                    $modeMeta["description"] ?? ""
                                ) ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </span>
                </div>
            </div>
    <?php if ($action === "discover" && $result !== null): ?>
        <?php
        $sample = $result["sample"] ?? [];
        $shown = array_slice($sample, 0, $displayLimit);
        $count = (int) ($result["count"] ?? 0);
        ?>
        <div class="fixallsql-card">
            <h4 style="margin-top:0;">Discover Results</h4>

            <div class="fixallsql-summary">
                <span class="fixallsql-badge fixallsql-badge-secondary">
                    Total discrepancies: <?= $h($count) ?>
                </span>
                <span class="fixallsql-badge fixallsql-badge-info">
                    Records processed: <?= $h(
                        $result["records_scanned"] ?? 0
                    ) ?>
                </span>
                <span class="fixallsql-badge fixallsql-badge-info">
                    Rows displayed: <?= $h(count($shown)) ?>
                </span>
            </div>

            <?php if ($count === 0): ?>
                <p><strong>No discrepancies found.</strong></p>
            <?php else: ?>                
                <?php if (!empty($result["hit_processing_limit"])): ?>
                    <div class="fixallsql-limit-note">
                        Showing up to <?php echo (int) $form[
                            "discrepancy_limit"
                        ]; ?> discrepancies. Additional issues may exist.
                    </div>
                <?php endif; ?>
                <div class="fixallsql-table-wrap">
                    <table class="fixallsql-table">
                        <thead>
                            <tr>
                                <th><input type="checkbox" id="select-all-records" checked></th>
                                <th>Record</th>
                                <th>Event ID</th>
                                <th>Instance</th>
                                <th>Repeat Instrument</th>
                                <th>Field</th>
                                <th>Current</th>
                                <th>Expected</th>
                                <th>Status</th>
                                <th>Reason</th>
                                <th>Selection Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($shown as $row): ?>
                                <?php
                                $statusClass = "";
                                $status = (string) ($row["status"] ?? "");

                                if ($status === "unresolved") {
                                    $statusClass =
                                        "fixallsql-status-unresolved";
                                }

                                $record = $row["record"] ?? "";
                                ?>
                                <tr data-record="<?= $h($record) ?>">
                                    <td>
                                        <?php $value = json_encode([
                                            "record" => $row["record"] ?? "",
                                            "field" => $row["field"] ?? "",
                                            "form" => $row["form"] ?? "",
                                            "current" => $row["current"] ?? "",
                                            "expected" =>
                                                $row["expected"] ?? "",
                                            "status" => $row["status"] ?? "",
                                            "event_id" =>
                                                $row["event_id"] ?? "",
                                            "instance" => $row["instance"] ?? 1,
                                            "repeat_instrument" =>
                                                $row["repeat_instrument"] ?? "",
                                        ]); ?>
                                        <input
                                            type="checkbox"
                                            class="fix-record-checkbox"
                                            value="<?= $h($value) ?>"
                                            checked
                                        >
                                    </td>
                                    <td><?= $h($record) ?></td>
                                    <td><?= $h($row["event_id"] ?? "") ?></td>
                                    <td><?= $h($row["instance"] ?? "") ?></td>
                                    <td><?= $h(
                                        $row["repeat_instrument"] ?? ""
                                    ) ?></td>
                                    <td><?= $h($row["field"] ?? "") ?></td>
                                    <td><?= $h($row["current"] ?? "") ?></td>
                                    <td><?= $h($row["expected"] ?? "") ?></td>
                                    <td class="<?= $h($statusClass) ?>"><?= $h($status) ?></td>
                                    <td><?= $h($row["reason"] ?? "") ?></td>
                                    <td><?= $h(
                                        $row["selection_reason"] ?? ""
                                    ) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if ($action === "fix" && $result !== null): ?>
        <?php
        $details = $result["details"] ?? [];
        $shown = array_slice($details, 0, $displayLimit);
        ?>
        <div class="fixallsql-card">
            <h4 style="margin-top:0;">Fix Results</h4>

            <div class="fixallsql-summary">
                <span class="fixallsql-badge fixallsql-badge-info">Records processed: <?= $h(
                    $result["records_scanned"] ?? 0
                ) ?></span>
                <span class="fixallsql-badge fixallsql-badge-secondary">Attempted: <?= $h(
                    $result["attempted"] ?? 0
                ) ?></span>
                <span class="fixallsql-badge fixallsql-badge-success">Fixed: <?= $h(
                    $result["fixed"] ?? 0
                ) ?></span>
                <span class="fixallsql-badge fixallsql-badge-info">Unchanged: <?= $h(
                    $result["unchanged"] ?? 0
                ) ?></span>
                <span class="fixallsql-badge fixallsql-badge-warning">Locked: <?= $h(
                    $result["locked"] ?? 0
                ) ?></span>
                <span class="fixallsql-badge fixallsql-badge-warning">Manual: <?= $h(
                    $result["manual"] ?? 0
                ) ?></span>
                <span class="fixallsql-badge fixallsql-badge-danger">Errors: <?= $h(
                    $result["errors"] ?? 0
                ) ?></span>
            </div>

            <?php if (empty($details)): ?>
                <p><strong>No detail rows returned.</strong></p>
            <?php else: ?>
                <?php if (count($details) > $displayLimit): ?>
                    <p class="fixallsql-muted">
                        Showing the first <?= $h($displayLimit) ?> detail rows.
                    </p>
                <?php endif; ?>

                <div class="fixallsql-table-wrap">
                    <table class="fixallsql-table">
                        <thead>
                            <tr>
                                <th>Record</th>
                                <th>Event ID</th>
                                <th>Instance</th>
                                <th>Repeat Instrument</th>
                                <th>Field</th>
                                <th>From</th>
                                <th>To</th>
                                <th>Status</th>
                                <th>Reason / Error</th>
                                <th>Link</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($shown as $row): ?>
                                <?php
                                $status = (string) ($row["status"] ?? "");
                                $statusClass = "";

                                if ($status === "fixed") {
                                    $statusClass = "fixallsql-status-fixed";
                                } elseif ($status === "error") {
                                    $statusClass = "fixallsql-status-error";
                                } elseif ($status === "manual") {
                                    $statusClass = "fixallsql-status-manual";
                                } elseif ($status === "locked") {
                                    $statusClass = "fixallsql-status-locked";
                                } elseif ($status === "unchanged") {
                                    $statusClass = "fixallsql-status-unchanged";
                                }

                                $reasonText =
                                    $row["reason"] ?? ($row["error"] ?? "");
                                ?>
                                <tr>
                                    <td><?= $h($row["record"] ?? "") ?></td>
                                    <td><?= $h($row["event_id"] ?? "") ?></td>
                                    <td><?= $h($row["instance"] ?? "") ?></td>
                                    <td><?= $h(
                                        $row["repeat_instrument"] ?? ""
                                    ) ?></td>
                                    <td><?= $h($row["field"] ?? "") ?></td>
                                    <td><?= $h(
                                        $row["from"] ?? ($row["current"] ?? "")
                                    ) ?></td>
                                    <td><?= $h(
                                        $row["to"] ?? ($row["expected"] ?? "")
                                    ) ?></td>
                                    <td class="<?= $h($statusClass) ?>"><?= $h($status
                                    ) ?></td>
                                    <td><?= $h($reasonText) ?></td>
                                    <td>
                                        <?php if (!empty($row["link"])): ?>
                                            <a href="<?= $h(
                                                $row["link"]
                                            ) ?>" target="_blank" rel="noopener noreferrer">Open Record</a>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
     </form>
    </div>
    <script>
    $(function () {
        $('#scope_instruments').select2({
            width: '100%',
            placeholder: 'All instruments',
            allowClear: true,
            closeOnSelect: false
        });

        $('#scope_fields').select2({
            width: '100%',
            placeholder: 'All fields',
            allowClear: true,
            closeOnSelect: false,
        });

        $('#scope_events').select2({
            width: '100%',
            placeholder: 'All events',
            allowClear: true,
            closeOnSelect: false,
        });
  
        const $instrumentSelect = $('#scope_instruments');
        const $fieldSelect = $('#scope_fields');
        const $eventSelect = $('#scope_events');

        const allFieldOptions = $fieldSelect.find('option').map(function () {
            return {
                value: this.value,
                text: $(this).text(),
                form: $(this).data('form') || ''
            };
        }).get();

        const allEventOptions = $eventSelect.find('option').map(function () {
            return {
                value: this.value,
                text: $(this).text(),
                forms: ($(this).data('forms') || '').toString().split(',').filter(Boolean)
            };
        }).get();

        function rebuildFieldOptions() {
            const selectedInstruments = $instrumentSelect.val() || [];
            const currentSelectedFields = new Set($fieldSelect.val() || []);

            const filteredOptions = allFieldOptions.filter(function (opt) {
                return selectedInstruments.length === 0 || selectedInstruments.includes(String(opt.form));
            });

            const nextSelectedValues = filteredOptions
                .filter(opt => currentSelectedFields.has(opt.value))
                .map(opt => opt.value);

            const wasOpen = $fieldSelect.data('select2') && $fieldSelect.data('select2').isOpen();

            $fieldSelect.empty();

            filteredOptions.forEach(function (opt) {
                const option = new Option(
                    opt.text,
                    opt.value,
                    false,
                    nextSelectedValues.includes(opt.value)
                );
                option.dataset.form = opt.form;
                $fieldSelect.append(option);
            });

            $fieldSelect.trigger('change');

            if (wasOpen) {
                $fieldSelect.select2('open');
            }
        }

        function rebuildEventOptions() {
            const selectedInstruments = $instrumentSelect.val() || [];
            const currentSelectedEvents = new Set(($eventSelect.val() || []).map(String));

            const filteredOptions = allEventOptions.filter(function (opt) {
                if (selectedInstruments.length === 0) return true;
                return opt.forms.some(form => selectedInstruments.includes(String(form)));
            });

            const nextSelectedValues = filteredOptions
                .filter(opt => currentSelectedEvents.has(String(opt.value)))
                .map(opt => String(opt.value));

            const wasOpen = $eventSelect.data('select2') && $eventSelect.data('select2').isOpen();

            $eventSelect.empty();

            filteredOptions.forEach(function (opt) {
                const option = new Option(
                    opt.text,
                    opt.value,
                    false,
                    nextSelectedValues.includes(String(opt.value))
                );
                option.dataset.forms = opt.forms.join(',');
                $eventSelect.append(option);
            });

            $eventSelect.trigger('change');

            if (wasOpen) {
                $eventSelect.select2('open');
            }
        }

        $instrumentSelect.on('change', function () {
            rebuildFieldOptions();
            rebuildEventOptions();
        });

        rebuildFieldOptions();
        rebuildEventOptions();
   
        $(document).on('change', 'input[name="confirm_live_run"]', function () {
            $('#fix-sql-btn').prop('disabled', !this.checked);
        });

        $(document).ready(function () {
            $('input[name="confirm_live_run"]').trigger('change');
        });

        $(document).on('change', '#select-all-records', function () {
            $('.fix-record-checkbox').prop('checked', $(this).is(':checked'));
        });

        let lastClickedAction = null;

        $('button[type=submit]').on('click', function () {
            lastClickedAction = $(this).val();
        });

        $('form').on('submit', function () {
            const form = $(this);
            const action = lastClickedAction;

            if (action !== 'fix') return;

            const selected = [];

            $('.fix-record-checkbox:checked').each(function () {
                selected.push($(this).val());
            });

            form.find('input[type="hidden"][name="selected_records[]"]').remove();

            selected.forEach(function (val) {
                $('<input>')
                    .attr({
                        type: 'hidden',
                        name: 'selected_records[]',
                        value: val
                    })
                    .appendTo(form);
            });
        });
    });
    </script>
</div>
