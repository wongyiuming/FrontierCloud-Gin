package business

// These queries examine scalar durable facts, not caller-supplied state or
// unbounded plan/recording JSON. They never grant physical cleanup/revocation.
func retirementPeerMigrations(member, master, relationship string, now int64) []retirementQuery {
	journals := `migration_storage_journal j
 LEFT JOIN migration_tasks t ON t.task_id=j.task_id
 LEFT JOIN migration_units u ON u.task_id=j.task_id AND u.unit_id=j.unit_id
 LEFT JOIN migration_peer_bindings b ON b.task_id=j.task_id AND b.logical_id=j.logical_id
 WHERE t.task_id IS NULL OR u.unit_id IS NULL OR b.logical_id IS NULL
 OR t.state NOT IN ('completed','cancelled')
 OR j.master_id<>t.master_id OR j.source_id<>t.source_id OR j.target_id<>t.target_id
 OR t.master_id<>? OR (t.source_id<>? AND t.target_id<>?)
 OR (t.source_id=? AND t.source_relationship<>?) OR (t.target_id=? AND t.target_relationship<>?)
 OR u.resource_kind<>j.resource_kind OR LENGTH(j.source_version)<>64 OR LENGTH(j.sha256)<>64 OR LENGTH(b.binding_sha256)<>64
 OR NOT (
  (u.state='cleaned' AND u.committed_at>0 AND u.cleanup_after>=u.committed_at+3600 AND u.cleanup_after<=?
   AND ((j.source_id=? AND j.state='deleted') OR (j.target_id=? AND j.state IN ('published','deleted'))))
  OR (t.state='cancelled' AND u.state='cancelled' AND u.committed_at=0 AND u.cleanup_after=0
   AND ((j.source_id=? AND j.state='receiving') OR (j.target_id=? AND j.state IN ('aborted','deleted'))))
 )`
	tasks := `migration_tasks t
 LEFT JOIN (SELECT task_id,COUNT(*) AS objects,COALESCE(SUM(expected_bytes),0) AS bytes FROM migration_storage_journal GROUP BY task_id) j ON j.task_id=t.task_id
 LEFT JOIN (SELECT task_id,COALESCE(SUM(object_count),0) AS objects,COALESCE(SUM(total_bytes),0) AS bytes FROM migration_units GROUP BY task_id) u ON u.task_id=t.task_id
 WHERE (t.source_id=? OR t.target_id=?) AND t.state IN ('completed','cancelled') AND (
 t.object_count<>COALESCE(j.objects,0)
 OR t.total_bytes<>COALESCE(j.bytes,0)
 OR t.object_count<>COALESCE(u.objects,0)
 OR t.total_bytes<>COALESCE(u.bytes,0)
 )`
	units := `migration_units u LEFT JOIN migration_tasks t ON t.task_id=u.task_id
 LEFT JOIN (SELECT task_id,unit_id,COUNT(*) AS objects,COALESCE(SUM(expected_bytes),0) AS bytes FROM migration_storage_journal GROUP BY task_id,unit_id) j ON j.task_id=u.task_id AND j.unit_id=u.unit_id
 WHERE
 t.task_id IS NULL OR ((t.source_id=? OR t.target_id=?) AND t.state IN ('completed','cancelled') AND (
 LENGTH(u.source_version)<>64
 OR u.object_count<>COALESCE(j.objects,0)
 OR u.total_bytes<>COALESCE(j.bytes,0)
 OR NOT (
 (u.state='cleaned' AND u.committed_at>0 AND u.cleanup_after>=u.committed_at+3600 AND u.cleanup_after<=?)
 OR (t.state='cancelled' AND u.state='cancelled' AND u.committed_at=0 AND u.cleanup_after=0)
 )))`
	return []retirementQuery{
		{"migration_journals", journals, "j.task_id", "reconcile_peer_task_and_file_receipts", []any{master, member, member, member, relationship, member, relationship, now, member, member, member, member}},
		{"migration_terminal_rosters", tasks, "t.task_id", "reconcile_terminal_task_unit_and_object_rosters", []any{member, member}},
		{"migration_unit_receipts", units, "u.task_id", "reconcile_terminal_task_unit_and_object_rosters", []any{member, member, now}},
	}
}
