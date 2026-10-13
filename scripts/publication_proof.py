"""Validate completed component jobs in the active trusted publication attempt."""
if __package__:
    from . import trusted_native_publish as publication
else:
    import trusted_native_publish as publication

REPOSITORY = publication.REPOSITORY
COMPONENTS = publication.COMPONENTS
PUBLISH_NAME = "Publish native images"
require = publication.require
positive = publication.positive

def publication_jobs(read, plan):
    run = read(f'/actions/runs/{plan["publish_run_id"]}')
    workflow = read('/actions/workflows/publish-images.yml')
    require(positive(workflow.get('id')) and workflow.get('path') == '.github/workflows/publish-images.yml' and
            workflow.get('name') == PUBLISH_NAME, 'Unexpected publication workflow')
    require(run.get('id') == plan['publish_run_id'] and run.get('run_attempt') == plan['publish_run_attempt'] and
            run.get('workflow_id') == workflow['id'] and run.get('path') == workflow['path'] and
            run.get('event') == 'workflow_run' and run.get('status') == 'in_progress' and
            run.get('conclusion') is None and run.get('head_repository', {}).get('full_name') == REPOSITORY,
            'Alias promotion must belong to this active trusted publication attempt')
    document = read(f'/actions/runs/{plan["publish_run_id"]}/attempts/{plan["publish_run_attempt"]}/jobs?per_page=100')
    jobs = document.get('jobs')
    require(isinstance(jobs, list) and type(document.get('total_count')) is int and
            document['total_count'] == len(jobs) and len(jobs) < 100, 'Incomplete publication job proof')
    expected = {'publish (' + component + ')' for component in COMPONENTS}
    actual = [job for job in jobs if job.get('name') in expected]
    require(len(actual) == len(COMPONENTS) and {job['name'] for job in actual} == expected and
            all(job.get('run_id') == plan['publish_run_id'] and
                job.get('status') == 'completed' and job.get('conclusion') == 'success' for job in actual),
            'All exact publication jobs must succeed before alias promotion')


