<?php
namespace OSUCOMRIT\FixAllSql;

use ExternalModules\AbstractExternalModule;

class FixAllSql extends AbstractExternalModule
{
    const DEFAULT_SELECTION_MODE = "keep_if_valid";
    private const MAX_RECORD_RANGE_SIZE = 10000;
    private const DEFAULT_DISCREPANCY_LIMIT = 1000;
    private const MAX_DISCREPANCY_LIMIT = 5000;

    /** @var array */
    private $repeatConfigCache = [];

    /** @var array */
    private $formFieldsCache = [];

    private const SELECTION_MODE_DETAILS = [
        "keep_if_valid" => [
            "label" => "keep if valid",
            "description" => "keep the current value if it is one of the SQL return values",
        ],
        "first" => [
            "label" => "first",
            "description" => "use the first SQL return value",
        ],
        "min" => [
            "label" => "min",
            "description" => "use the lowest SQL return value",
        ],
        "max" => [
            "label" => "max",
            "description" => "use the highest SQL return value",
        ],
        "none" => [
            "label" => "none",
            "description" => "do not auto-select a value when SQL returns multiple values",
        ],
    ];

    //Discover workflow:
    public function discover($project_id, array $overrides = [])
    {
        $this->guard($project_id);

        $Proj = $this->project();
        $options = $this->getRunOptions($project_id, $overrides);

        $sqlFields = $this->sqlFields($project_id, $options);

        if (empty($sqlFields)) {
            return [
                "count" => 0,
                "sample" => [],
                "records" => [],
                "items" => [],
                "records_scanned" => 0,
            ];
        }

        $records = $this->getTargetRecords($project_id, $options);

        $result = $this->discoverList(
            $project_id,
            $Proj,
            $sqlFields,
            $options,
            $records
        );

        return [
            "count" => $result["count"],
            "records_scanned" => count($result["records"] ?? []),
            "sample" => $result["items"] ?? [],
        ];
    }

    public function getMaxDiscrepancyLimit(): int
    {
        return $this->getEffectiveMaxDiscrepancyLimit();
    }

    public function getDefaultDiscrepancyLimit(): int
    {
        $configured = (int) $this->getProjectSetting("default_discrepancy_limit");
        $default = $configured > 0 ? $configured : self::DEFAULT_DISCREPANCY_LIMIT;

        return min($default, $this->getEffectiveMaxDiscrepancyLimit());
    }

    public function getDefaultSelectionMode(): string
    {
        $configured = trim((string) $this->getProjectSetting("selection_mode"));

        if ($this->isValidSelectionMode($configured)) {
            return $configured;
        }

        return self::DEFAULT_SELECTION_MODE;
    }

    public function getSelectionModeDetails(): array
    {
        return self::SELECTION_MODE_DETAILS;
    }

    public function getDataTable($pid)
    {
        return method_exists("\\REDCap", "getDataTable")
            ? \REDCap::getDataTable($pid)
            : "redcap_data";
    }

    //Fix workflow:
    public function fix($project_id, array $overrides = [])
    {
        $this->guard($project_id);

        $Proj = $this->project();
        $options = $this->getRunOptions($project_id, $overrides);
 
        $rawItems = $overrides["selected_items"] ?? [];

        if (!empty($options["simulate_only"])) {
            $rawItems = [];
        }

        $selectedItems = [];

        foreach ($rawItems as $item) {
            if (is_array($item)) {
                $selectedItems[] = $item;
                continue;
            }

            if (is_string($item) && trim($item) !== "") {
                $decoded = json_decode($item, true);
                if (is_array($decoded)) {
                    $selectedItems[] = $decoded;
                }
            }
        }

        //Security boundary:
        //Client-submitted items may only identify selected findings.
        //The expected value used for remediation must be re-derived server-side.
        $sqlFields = $this->sqlFields($project_id, $options);
        $records = $this->getTargetRecords($project_id, $options);

        $discovered = $this->discoverList(
            $project_id,
            $Proj,
            $sqlFields,
            $options,
            $records
        );

        $discoveredItems =$discovered["items"] ?? [];
     
        //Distinguish a selection (run against current discovery)
        //from an explicit empty selection (user chose nothing; do not run a bulk fix).
        $selectionWasProvided =
            array_key_exists("selected_items", $overrides);

        if ($selectionWasProvided && empty($selectedItems)) {
            throw new \Exception(
                "No discrepancies were selected for remediation."
            );
        }

        if (!$selectionWasProvided) {
            $items = $discoveredItems;
        } else {

            $discoveredByKey = [];
            $seenSelectionKeys = [];

            foreach ($discoveredItems as $discoveredItem) {
                if (!is_array($discoveredItem)) {
                    continue;
             }

                $key = $this->remediationKey($discoveredItem);

               if ($key !== "") {
                    $discoveredByKey[$key] = $discoveredItem;
                }
            }

            $items = [];

            foreach ($selectedItems as $selectedItem) {
                if (!is_array($selectedItem)) {
                    continue;
                }

                $key = $this->remediationKey($selectedItem);

                //Posted rows are trusted only as identifiers; any stale or tampered row must fail closed.
                if ($key === "" || !isset($discoveredByKey[$key])) {
                    throw new \Exception(
                        "Selected finding is no longer valid. Re-run discovery and try again."
                    );
                }

                if (isset($seenSelectionKeys[$key])) {
                    continue;
                }
                $seenSelectionKeys[$key] = true;

                //Important: Use the rediscovered server-side item. Do not use posted expected/current values.
                $items[] = $discoveredByKey[$key];
            }
        }

        $recordsForLocking = array_values(
            array_unique(
                array_filter(
                    array_map(function ($item) {
                        return $item["record"] ?? "";
                    }, $items)
                )
            )
        );

        $report = [
            "records_scanned" => count($recordsForLocking),
            "attempted" => 0,
            "fixed" => 0,
            "unchanged" => 0,
            "locked" => 0,
            "manual" => 0,
            "errors" => 0,
            "details" => [],
        ];

        if (empty($items)) {
            return $report;
        }

        $Locking = new \Locking();
        $Locking->findLocked($Proj, $recordsForLocking);
        $Locking->findLockedWholeRecord($project_id, $recordsForLocking);

        foreach ($items as $item) {

            if (!is_array($item)) {
                continue;
            }

            if (($item["expected"] ?? "") === "") {
                $report["unchanged"]++;
                $report["details"][] = [
                    "record" => $item["record"] ?? "",
                    "event_id" => $item["event_id"] ?? "",
                    "instance" => $item["instance"] ?? 1,
                    "repeat_instrument" => $item["repeat_instrument"] ?? "",
                    "field" => $item["field"] ?? "",
                    "status" => "unchanged",
                    "reason" => "skipped item with empty expected value",
                ];
                continue;
            }

            $report["attempted"]++;

            $record = (string) $item["record"];
            $field = (string) $item["field"];
            $form = (string) $item["form"];
            $event_id = (int) $item["event_id"];
            $instance = (int) $item["instance"];
            $repeatInstrument = (string) $item["repeat_instrument"];
            $expected = (string) $item["expected"];

            $arm_id = $Proj->eventInfo[$event_id]["arm_id"] ?? null;

            $lockedWhole =
                $arm_id !== null &&
                isset($Locking->lockedWhole[$record][$arm_id]);
            $lockedField = isset(
                $Locking->locked[$record][$event_id][$instance][$field]
            );

            if ($lockedWhole || $lockedField) {
                $report["locked"]++;
                $report["details"][] = [
                    "record" => $record,
                    "event_id" => $event_id,
                    "instance" => $instance,
                    "repeat_instrument" => $repeatInstrument,
                    "field" => $field,
                    "status" => "locked",
                    "link" => $this->buildRecordLink(
                        $project_id,
                        $record,
                        $form,
                        $field,
                        $event_id,
                        $instance
                    ),
                ];
                continue;
            }

            $current = $this->getCurrentValue(
                $project_id,
                $record,
                $field,
                $event_id,
                $instance
            );
            $current = $current === null ? "" : (string) $current;

            $currentNorm = trim((string) $current);
            $expectedNorm = trim((string) $expected);

            if ($currentNorm === $expectedNorm) {
                $report["unchanged"]++;
                $report["details"][] = [
                    "record" => $record,
                    "event_id" => $event_id,
                    "instance" => $instance,
                    "repeat_instrument" => $repeatInstrument,
                    "field" => $field,
                    "status" => "unchanged",
                ];
                continue;
            }

            $payloadRow = $this->buildSavePayloadRow(
                $Proj,
                $record,
                $field,
                $expected,
                $event_id,
                $repeatInstrument,
                $instance
            );

            $saveResult = \REDCap::saveData(
                $project_id,
                "json",
                json_encode([$payloadRow]),
                "overwrite"
            );

            $classification = $this->classifySaveResult($saveResult);

            //Re-read the value after save and trust the persisted value.
            $after = $this->getCurrentValue(
                $project_id,
                $record,
                $field,
                $event_id,
                $instance
            );
            $after = $after === null ? "" : (string) $after;

            $afterNorm = trim((string) $after);
            $expectedNorm = trim((string) $expected);

            if ($afterNorm === $expectedNorm) {
                $report["fixed"]++;
                $report["details"][] = [
                    "record" => $record,
                    "event_id" => $event_id,
                    "instance" => $instance,
                    "repeat_instrument" => $repeatInstrument,
                    "field" => $field,
                    "from" => $current,
                    "to" => $expected,
                    "status" => "fixed",
                ];
            } elseif ($classification["status"] === "manual") {
                $report["manual"]++;
                $report["details"][] = [
                    "record" => $record,
                    "event_id" => $event_id,
                    "instance" => $instance,
                    "repeat_instrument" => $repeatInstrument,
                    "field" => $field,
                    "current" => $current,
                    "expected" => $expected,
                    "status" => "manual",
                    "reason" => $classification["reason"],
                    "error" => $classification["error"],
                    "link" => $this->buildRecordLink(
                        $project_id,
                        $record,
                        $form,
                        $field,
                        $event_id,
                        $instance
                    ),
                ];
            } else {
                $report["errors"]++;
                $report["details"][] = [
                    "record" => $record,
                    "event_id" => $event_id,
                    "instance" => $instance,
                    "repeat_instrument" => $repeatInstrument,
                    "field" => $field,
                    "status" => "error",
                    "error" => $classification["error"],
                    "link" => $this->buildRecordLink(
                        $project_id,
                        $record,
                        $form,
                        $field,
                        $event_id,
                        $instance
                    ),
                ];
            }
        }
        return $report;
    }

    //Guard / options / project helpers:

    private function guard($project_id)
    {
        $rights = \REDCap::getUserRights(USERID);

        if (empty($rights[USERID]) || empty($rights[USERID]["design"])) {
            throw new \Exception("Insufficient rights: design/admin required.");
        }

        if (!$this->getSystemSetting("enable_module")) {
            throw new \Exception("Module disabled by system setting.");
        }

        $recordCount = \Records::getRecordCount($project_id);
        $maxThreshold = (int) $this->getSystemSetting("max_records_threshold");

        if ($maxThreshold > 0 && $recordCount > $maxThreshold) {
            throw new \Exception(
                "Safety cut-off: {$recordCount} > {$maxThreshold}"
            );
        }
    }

    private function project()
    {
        global $Proj;
        return $Proj;
    }

    private function getRunOptions($project_id, array $overrides = [])
    {
        $Proj = $this->project();

        $configuredFields = $overrides["scope_fields"] ?? [];
        $configuredInstruments = $overrides["scope_instruments"] ?? "";

        $configuredSpecificRecordsText =
            $overrides["specific_records_text"] ?? "";

        $specificRecords = [];

        if (
            is_string($configuredSpecificRecordsText) &&
            trim($configuredSpecificRecordsText) !== ""
        ) {
            foreach (explode(",", $configuredSpecificRecordsText) as $part) {
                $part = trim($part);
                if ($part === "") {
                    continue;
                }

                if (strpos($part, "-") !== false) {
                    [$start, $end] = array_map(
                        "intval",
                        explode("-", $part, 2)
                    );
                    if ($start > 0 && $end >= $start) {

                        $rangeSize = ($end - $start) + 1;

                        $maxRangeSize = $this->getEffectiveMaxRecordRangeSize();

                        if ($rangeSize > $maxRangeSize) {
                            throw new \Exception(
                                "Record range '{$part}' exceeds the maximum allowed size of " .
                                $maxRangeSize .
                                " records."
                            );
                        }

                        $specificRecords = array_merge(
                            $specificRecords,
                            range($start, $end)
                        );
                    }
                } else {
                    $specificRecords[] = $part;
                }
            }

            $specificRecords = array_values(
                array_unique(array_map("strval", $specificRecords))
            );
        }

        $configuredSimulate = $overrides["simulate_only"] ?? 0;
        $configuredSelection =
            $overrides["selection_mode"] ??
            $this->getDefaultSelectionMode();
        
        $limit = (int) (
            $overrides["discrepancy_limit"] ??
            $this->getDefaultDiscrepancyLimit()
        );

        //Fail fast on invalid limit values to avoid long-running full scans.
        if ($limit <= 0) {
            throw new \Exception(
                "Discrepancy scan limit must be at least 1."
            );
        }

        $limit = min($limit, $this->getEffectiveMaxDiscrepancyLimit());

        $scopeInstruments = is_array($configuredInstruments)
            ? $configuredInstruments
            : [];

        $eventIds =
            isset($overrides["scope_events"]) &&
            is_array($overrides["scope_events"])
                ? array_map("intval", $overrides["scope_events"])
                : [];
        
        $validEventIds = array_keys($Proj->eventInfo);

        //Keep event scope constrained to events that actually exist in this project.
        $eventIds = array_values(
            array_intersect($eventIds, $validEventIds)
        );

        $scopeFields = is_array($configuredFields)
            ? array_values(array_filter(array_map("strval", $configuredFields)))
            : [];

        $selectionMode = trim((string) $configuredSelection);
        if (!$this->isValidSelectionMode($selectionMode)) {
            $selectionMode = self::DEFAULT_SELECTION_MODE;
        }

        $validInstruments = $this->resolveScopedInstruments(
            $Proj,
            $scopeInstruments
        );

        $allEventNames = \REDCap::getEventNames(true);

        if (is_array($allEventNames) && !empty($allEventNames)) {
            $allEventIds = array_keys($allEventNames);
        } else {
            $allEventIds = [];
        }

        return [
            "scope_fields" => $scopeFields,
            "scope_events" => $eventIds,
            "scope_instruments" => $validInstruments,
            "event_ids" => !empty($eventIds) ? $eventIds : $allEventIds,
            "specific_records" => $specificRecords,
            "simulate_only" => !empty($configuredSimulate),
            "selection_mode" => $selectionMode,
            "discrepancy_limit" => $limit,
        ];
    }

    private function isValidSelectionMode($selectionMode): bool
    {
        return is_string($selectionMode) &&
            array_key_exists($selectionMode, self::SELECTION_MODE_DETAILS);
    }

    private function getEffectiveMaxRecordRangeSize(): int
    {
        $configured = (int) $this->getSystemSetting("max_record_range_size");

        if ($configured <= 0) {
            return self::MAX_RECORD_RANGE_SIZE;
        }

        return min($configured, self::MAX_RECORD_RANGE_SIZE);
    }

    private function getEffectiveMaxDiscrepancyLimit(): int
    {
        $configured = (int) $this->getSystemSetting("max_discrepancy_limit");

        if ($configured <= 0) {
            return self::MAX_DISCREPANCY_LIMIT;
        }

        return min($configured, self::MAX_DISCREPANCY_LIMIT);
    }

    private function resolveScopedInstruments($Proj, array $scopeInstruments)
    {
        if (empty($scopeInstruments)) {
            return [];
        }

        $scopeInstruments = array_values(
            array_filter(
                array_map(function ($v) {
                    return strtolower(trim((string) $v));
                }, $scopeInstruments)
            )
        );

        $instrumentNames = \REDCap::getInstrumentNames();

        $map = [];
        foreach (
            (array) $instrumentNames
            as $instrumentKey => $instrumentLabel
        ) {
            $map[strtolower((string) $instrumentKey)] = (string) $instrumentKey;
        }

        $resolved = [];
        foreach ($scopeInstruments as $entered) {
            if (isset($map[$entered])) {
                $resolved[] = $map[$entered];
            }
        }

        return array_values(array_unique($resolved));
    }

    private function getTargetRecords($project_id, array $options)
    {
        $recordIdField = \REDCap::getRecordIdField();

        $data = \REDCap::getData([
            "project_id" => $project_id,
            "return_format" => "array",
            "fields" => [$recordIdField],
        ]);

        $allRecords = is_array($data) ? array_keys($data) : [];

        if (!empty($options["specific_records"])) {
            $wanted = array_map("strval", $options["specific_records"]);
            return array_values(array_intersect($allRecords, $wanted));
        }

        return $allRecords;
    }

    //SQL field discovery and event applicability:
    public function sqlFields($project_id, array $options)
    {
        $Proj = $this->project();
        $fields = [];

        foreach ($Proj->metadata as $field => $meta) {
            $form = (string) ($meta["form_name"] ?? "");
            $type = strtolower(trim((string) ($meta["element_type"] ?? "")));
            $rawSql = trim((string) ($meta["element_enum"] ?? ""));

            if (
                !empty($options["scope_instruments"]) &&
                !in_array($form, $options["scope_instruments"], true)
            ) {
                continue;
            }

            if (
                !empty($options["scope_fields"]) &&
                !in_array($field, $options["scope_fields"], true)
            ) {
                continue;
            }

            if ($type !== "sql") {
                if ($rawSql === "" || stripos($rawSql, "select") !== 0) {
                    continue;
                }
            } elseif ($rawSql === "") {
                continue;
            }

            $fields[] = [
                "field" => $field,
                "form" => $form,
                "raw_sql" => $rawSql,
            ];
        }

        return $fields;
    }

    private function formAppliesToEvent($Proj, $form, $event_id)
    {
        if (!$Proj->longitudinal) {
            return true;
        }

        if (
            !isset($Proj->eventsForms[$event_id]) ||
            !is_array($Proj->eventsForms[$event_id])
        ) {
            return false;
        }

        return in_array($form, $Proj->eventsForms[$event_id], true);
    }

    private function uniqueEventName($Proj, $event_id)
    {
        $event_id = (int) $event_id;

        $eventNames = \REDCap::getEventNames(true, false);

        if (!empty($eventNames[$event_id])) {
            return (string) $eventNames[$event_id];
        }

        throw new \Exception(
            "Unable to resolve unique event name for event_id {$event_id}"
        );
    }

    //Repeat instrument awareness:
    private function getRepeatConfig($event_id, $form)
    {
        $cacheKey = $event_id . "|" . $form;

        if (isset($this->repeatConfigCache[$cacheKey])) {
            return $this->repeatConfigCache[$cacheKey];
        }

        $event_id = (int) $event_id;
        $sql = "
            SELECT form_name
            FROM redcap_events_repeat
            WHERE event_id = {$event_id}
        ";
        $q = db_query($sql);

        $config = [
            "is_repeating" => false,
            "repeat_instrument" => "",
            "repeat_type" => "none",
        ];

        if ($q) {
            while ($row = db_fetch_assoc($q)) {
                $rowForm = $row["form_name"];

                if ($rowForm === null) {
                    $config = [
                        "is_repeating" => true,
                        "repeat_instrument" => "",
                        "repeat_type" => "event",
                    ];
                    break;
                }

                if ((string) $rowForm === (string) $form) {
                    $config = [
                        "is_repeating" => true,
                        "repeat_instrument" => (string) $form,
                        "repeat_type" => "instrument",
                    ];
                    break;
                }
            }
        }

        $this->repeatConfigCache[$cacheKey] = $config;

        return $config;
    }

    private function getFormFieldNames($Proj, $form)
    {
        if (isset($this->formFieldsCache[$form])) {
            return $this->formFieldsCache[$form];
        }

        $fields = [];

        foreach ($Proj->metadata as $field => $meta) {
            if (($meta["form_name"] ?? "") === $form) {
                $fields[] = $field;
            }
        }

        $this->formFieldsCache[$form] = $fields;

        return $fields;
    }

    private function getInstancesForContext(
        $project_id,
        $record,
        $event_id,
        $form
    ) {
        $Proj = $this->project();
        $repeatConfig = $this->getRepeatConfig($event_id, $form);

        if (empty($repeatConfig["is_repeating"])) {
            return [1];
        }

        $formFields = $this->getFormFieldNames($Proj, $form);
        if (empty($formFields)) {
            return [1];
        }

        $project_id = (int) $project_id;
        $event_id = (int) $event_id;
        $recordEscaped = db_escape($record);
        $dataTable = preg_replace(
            "/[^A-Za-z0-9_]/",
            "",
            (string) $this->getDataTable($project_id)
        );

        if ($dataTable === "") {
            $dataTable = "redcap_data";
        }

        $fieldList = array_map(function ($field) {
            return "'" . db_escape($field) . "'";
        }, $formFields);

        $sql =
            "
            SELECT DISTINCT instance
            FROM {$dataTable}
            WHERE project_id = {$project_id}
              AND record = '{$recordEscaped}'
              AND event_id = {$event_id}
              AND field_name IN (" .
            implode(",", $fieldList) .
            ")
            ORDER BY instance
        ";

        $q = db_query($sql);
        $instances = [];

        if ($q) {
            while ($row = db_fetch_assoc($q)) {
                $instance = (int) ($row["instance"] ?? 1);
                if ($instance < 1) {
                    $instance = 1;
                }
                $instances[] = $instance;
            }
        }

        $instances = array_values(array_unique($instances));

        if (empty($instances)) {
            $instances = [1];
        }

        return $instances;
    }

    //Current value, SQL evaluation, and selection mode:
    private function getCurrentValue(
        $project_id,
        $record,
        $field,
        $event_id = null,
        $instance = 1
    ) {
        $Proj = $this->project();

        if (!$Proj->longitudinal) {
            $event_id = array_key_first((array) $Proj->eventInfo);
        }

        $event_id = (int) $event_id;
        $instance = (int) ($instance ?: 1);

        $data = \REDCap::getData(
            $project_id,
            "array",
            [$record],
            [$field],
            [$event_id]
        );

        if (empty($data[$record][$event_id])) {
            return null;
        }

        if ($instance > 1) {
            return $data[$record][$event_id][$instance][$field] ?? null;
        }

        if (isset($data[$record][$event_id][$field])) {
            return $data[$record][$event_id][$field];
        }

        if (isset($data[$record][$event_id][1][$field])) {
            return $data[$record][$event_id][1][$field];
        }

        return null;
    }

    private function sqlEnumForContext(
        $Proj,
        $field,
        $rawSql,
        $record,
        $event_id,
        $instance
    ) {
        if (\Piping::containsSpecialTags($rawSql)) {
            return \getSqlFieldEnum(
                $rawSql,
                $Proj->project_id,
                $record,
                $event_id,
                $instance,
                null,
                null,
                $Proj->metadata[$field]["form_name"]
            );
        }

        return \getSqlFieldEnum($rawSql);
    }

    private function resolveExpectedValue(
        array $parsed,
        $selectionMode,
        $current = null
    ) {
        $values = array_values(
            array_unique(array_map("strval", array_keys($parsed)))
        );

        if (count($values) === 0) {
            return [
                "ok" => false,
                "value" => null,
                "reason" => "empty_result",
            ];
        }

        if (count($values) === 1) {
            return [
                "ok" => true,
                "value" => $values[0],
                "reason" => "single_result",
            ];
        }

        switch ($selectionMode) {
            case "keep_if_valid":
                if (
                    $current !== null &&
                    in_array((string) $current, $values, true)
                ) {
                    return [
                        "ok" => true,
                        "value" => (string) $current,
                        "reason" => "kept_existing_valid",
                    ];
                }
                return [
                    "ok" => false,
                    "value" => null,
                    "reason" => "multiple_results_keep_if_valid_no_match",
                ];

            case "first":
                return [
                    "ok" => true,
                    "value" => $values[0],
                    "reason" => "multiple_results_first",
                ];

            case "min":
                return [
                    "ok" => true,
                    "value" => min($values),
                    "reason" => "multiple_results_min",
                ];

            case "max":
                return [
                    "ok" => true,
                    "value" => max($values),
                    "reason" => "multiple_results_max",
                ];

            case "none":
            default:
                return [
                    "ok" => false,
                    "value" => null,
                    "reason" => "multiple_results_disallowed",
                ];
        }
    }

    private function isSingleValueSqlQuery($sql)
    {
        $sql = strtoupper((string) $sql);

        return strpos($sql, "LIMIT 1") !== false ||
            strpos($sql, "MAX(") !== false ||
            strpos($sql, "MIN(") !== false ||
            strpos($sql, "COUNT(") !== false;
    }

    //Discovery engine:
    private function discoverList(
        $project_id,
        $Proj,
        array $sqlFields,
        array $options,
        array $records
    ) {
        $items = [];
        $recordsSeen = [];

        $discrepancyCount = 0;
        $limit = (int) ($options["discrepancy_limit"] ?? 1000);
        $hitLimit = false;

        $eventIds = !empty($options["event_ids"])
            ? $options["event_ids"]
            : array_keys($Proj->eventInfo);

        foreach ($records as $record) {
            $recordsSeen[] = $record;

            foreach ($eventIds as $event_id) {
                foreach ($sqlFields as $sf) {
                    $field = $sf["field"];
                    $form = $sf["form"];
                 
                    if (!$this->formAppliesToEvent($Proj, $form, $event_id)) {
                        continue;
                    }

                    $repeatConfig = $this->getRepeatConfig($event_id, $form);
                    $instances = $this->getInstancesForContext(
                        $project_id,
                        $record,
                        $event_id,
                        $form
                    );

                    foreach ($instances as $instance) {
                        $current = $this->getCurrentValue(
                            $project_id,
                            $record,
                            $field,
                            $event_id,
                            $instance
                        );
                        $current = $current === null ? "" : (string) $current;

                        $enum = $this->sqlEnumForContext(
                            $Proj,
                            $field,
                            $sf["raw_sql"],
                            $record,
                            $event_id,
                            $instance
                        );

                        if (
                            $enum === null ||
                            $enum === false ||
                            trim((string) $enum) === ""
                        ) {
                            continue;
                        }

                        if (strpos($enum, ",") !== false) {
                            $parts = array_map("trim", explode(",", $enum));
                            $unique = array_values(array_unique($parts));

                            if (count($unique) === 1) {
                                $enum = $unique[0];
                            }
                        }

                        if ($this->isSingleValueSqlQuery($sf["raw_sql"])) {
                            $parsed = \parseEnum($enum);

                            if (is_array($parsed) && !empty($parsed)) {
                                $values = array_values(
                                    array_unique(
                                        array_map("strval", array_keys($parsed))
                                    )
                                );

                                if (count($values) === 1) {
                                    $singleValue = $values[0];
                                } else {
                                    $singleValue =
                                        array_key_first($parsed) ??
                                        trim((string) $enum);
                                }
                            } else {
                                $singleValue = trim((string) $enum);
                            }

                            if ($singleValue === "") {
                                continue;
                            }

                            $resolved = [
                                "ok" => true,
                                "value" => $singleValue,
                                "reason" => "single_value_query",
                            ];
                        } else {
                            $parsed = \parseEnum($enum);

                            if (!is_array($parsed) || empty($parsed)) {
                                continue;
                            }

                            $resolved = $this->resolveExpectedValue(
                                $parsed,
                                $options["selection_mode"],
                                $current
                            );
                        }

                        if (empty($resolved["ok"])) {
                            $discrepancyCount++;

                            $items[] = [
                                "record" => $record,
                                "event_id" => $event_id,
                                "instance" => $instance,
                                "repeat_instrument" =>
                                    $repeatConfig["repeat_instrument"],
                                "field" => $field,
                                "form" => $form,
                                "current" => $current,
                                "expected" => null,
                                "raw_sql" => $sf["raw_sql"],
                                "reason" => $resolved["reason"],
                                "status" => "unresolved",
                            ];

                            if ($limit > 0 && $discrepancyCount >= $limit) {
                                $hitLimit = true;
                                break 4;
                            }

                            continue;
                        }

                        $expected = isset($resolved["value"])
                            ? (string) $resolved["value"]
                            : "";

                        $currentNorm = trim((string) $current);
                        $expectedNorm = trim((string) $expected);

                        if ($currentNorm !== $expectedNorm) {
                            $discrepancyCount++;

                            $items[] = [
                                "record" => $record,
                                "event_id" => $event_id,
                                "instance" => $instance,
                                "repeat_instrument" =>
                                    $repeatConfig["repeat_instrument"],
                                "field" => $field,
                                "form" => $form,
                                "current" => $current,
                                "expected" => $expected,
                                "raw_sql" => $sf["raw_sql"],
                                "reason" =>
                                    $currentNorm === "" ? "empty" : "mismatch",
                                "selection_reason" => $resolved["reason"],
                                "status" => "fixable",
                            ];

                            if ($limit > 0 && $discrepancyCount >= $limit) {
                                $hitLimit = true;
                                break 4;
                            }
                        }
                    }
                }
            }
        }

        return [
            "count" => $discrepancyCount,
            "items" => $items,
            "records" => array_values(array_unique($recordsSeen)),
            "hit_processing_limit" => $hitLimit,
        ];
    }

    //Save payload, result classification, and UI link:
    private function buildSavePayloadRow(
        $Proj,
        $record,
        $field,
        $value,
        $event_id = null,
        $repeatInstrument = "",
        $instance = 1
    ) {
        $row = [
            $Proj->table_pk => $record,
            $field => $value,
        ];

        if ($Proj->longitudinal && $event_id) {
            $row["redcap_event_name"] = $this->uniqueEventName(
                $Proj,
                $event_id
            );
        }

        $instance = (int) ($instance ?: 1);

        if ($repeatInstrument !== "") {
            $row["redcap_repeat_instrument"] = $repeatInstrument;
            $row["redcap_repeat_instance"] = $instance;
        } elseif ($instance > 1) {
            $row["redcap_repeat_instrument"] = "";
            $row["redcap_repeat_instance"] = $instance;
        }

        return $row;
    }

    private function classifySaveResult($result)
    {
        $errors = [];

        if (!empty($result["errors"]) && is_array($result["errors"])) {
            $errors = $result["errors"];
        }

        if (empty($errors)) {
            return [
                "status" => "ok",
                "error" => "",
                "reason" => "",
            ];
        }

        $errorText = implode("; ", $errors);
        $lower = strtolower($errorText);

        $manualIndicators = [
            "not a valid category",
            "validation",
            "invalid value",
            "out of range",
            "not considered valid",
        ];

        foreach ($manualIndicators as $indicator) {
            if (strpos($lower, strtolower($indicator)) !== false) {
                return [
                    "status" => "manual",
                    "error" => $errorText,
                    "reason" => "save-time validation failure",
                ];
            }
        }

        return [
            "status" => "error",
            "error" => $errorText,
            "reason" => "saveData returned error",
        ];
    }

    private function buildRecordLink(
        $pid,
        $record,
        $form,
        $field,
        $event_id = null,
        $instance = 1
    ) {
        $url = APP_PATH_WEBROOT . "DataEntry/index.php";

        $params = [
            "pid" => $pid,
            "id" => $record,
            "page" => $form,
            "fldfocus" => $field,
        ];

        if (!empty($event_id)) {
            $params["event_id"] = $event_id;
        }

        if (!empty($instance) && (int) $instance > 1) {
            $params["instance"] = (int) $instance;
        }

        return $url . "?" . http_build_query($params);
    }
    
    private function remediationKey(array $item): string
    {
        $record = trim((string) ($item["record"] ?? ""));
        $field = trim((string) ($item["field"] ?? ""));
        $eventId = (int) ($item["event_id"] ?? 0);
        $instance = (int) ($item["instance"] ?? 1);
        $repeatInstrument = trim((string) ($item["repeat_instrument"] ?? ""));

        if ($record === "" || $field === "" || $eventId <= 0) {
            return "";
        }

        return implode("|", [
            $record,
            $field,
            (string) $eventId,
            (string) $instance,
            $repeatInstrument,
        ]);
    }
}
