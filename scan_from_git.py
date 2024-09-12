"""
1. get token (auth header)
2. get team id
3. create project with default configuration, will get project id
4. set remote source setting to git
5[optional]. set issue tracking system as jira by id
6. set data retention settings by project id
7. define SAST scan settings
8. create new scan, will get a scan id
9. get scan details by scan id
10[optional]: get scan queue details by scan id
11[optional]. get statistics results by scan id
12. register scan report
13. get report status by id
14. get report by id
15[optional]. filter report results
"""
import json
import time
from zipfile import ZipFile
from os.path import normpath, join, dirname, exists
from datetime import datetime
from CheckmarxPythonSDK.CxRestAPISDK import TeamAPI
from CheckmarxPythonSDK.CxRestAPISDK import ProjectsAPI
from CheckmarxPythonSDK.CxRestAPISDK import ScansAPI
from CheckmarxPythonSDK.CxRestAPISDK import QueriesAPI
from CheckmarxPythonSDK.external.sarif import create_sarif_report_from_sast_xml
from CheckmarxPythonSDK.CxRestAPISDK.CxSastXML.xml_results import obj_to_dict
from CheckmarxPythonSDK.CxODataApiSDK.HttpRequests import get_request
from CheckmarxPythonSDK.CxOne import (
    create_a_pre_signed_url_to_upload_files,
    upload_zip_content_for_scanning,
    create_byor_import,
)
from CheckmarxPythonSDK.CxOne.dto import (
    ImportRequest
)
from bs4 import BeautifulSoup


def get_all_query_ids_from_scan(scan_id):
    relative_url = "/Cxwebinterface/odata/v1/Scans({id})/Results".format(id=scan_id)
    relative_url += "?$select=QueryId"
    item_list = get_request(relative_url=relative_url)
    results = [item.get("QueryId") for item in item_list]
    return results


def scan_from_git(team_full_name, project_name, report_type, git_repo_url, branch, report_folder=None, pat=None):
    """

    Args:
        team_full_name (str):
        project_name (str):
        report_type (str): "PDF", "XML"
        git_repo_url (str):
        branch (str):
        report_folder (str):

    Returns:

    """
    if not report_folder or not exists(report_folder):
        report_folder = dirname(__file__)
    param_str = "team_full_name: {}, \n".format(team_full_name)
    param_str += "project_name: {}, \n".format(project_name)
    param_str += "report_type: {}, \n".format(report_type)
    param_str += "git_repo_url: {}, \n".format(git_repo_url)
    param_str += "branch: {}, \n".format(branch)
    param_str += "report_folder: {}".format(report_folder)
    print(param_str)

    projects_api = ProjectsAPI()
    team_api = TeamAPI()
    scan_api = ScansAPI()

    # 2. get team id
    print("2. get team id")
    team_id = team_api.get_team_id_by_team_full_name(team_full_name)
    if not team_id:
        print("team: {} not exist".format(team_full_name))
        return

    project_id = projects_api.get_project_id_by_project_name_and_team_full_name(project_name=project_name,
                                                                                team_full_name=team_full_name)

    # 3. create project with default configuration, will get project id
    print("3. create project with default configuration, will get project id")
    if not project_id:
        project = projects_api.create_project_with_default_configuration(project_name=project_name, team_id=team_id)
        project_id = project.id
    print("project_id: {}".format(project_id))

    # 4. set remote source setting to git
    print("4. set remote source setting to git")
    projects_api.set_remote_source_setting_to_git(project_id=project_id, url=git_repo_url, branch=branch,
                                                  authentication='PAT', pat=pat)

    # 6. set data retention settings by project id
    print("6. set data retention settings by project id")
    projects_api.set_data_retention_settings_by_project_id(project_id=project_id, scans_to_keep=3)

    # 7. define SAST scan settings
    print("7. define SAST scan settings")
    preset_id = projects_api.get_preset_id_by_name(preset_name="All")
    print("preset id: {}".format(preset_id))
    # scan_api.define_sast_scan_settings(project_id=project_id, preset_id=preset_id)

    projects_api.set_project_exclude_settings_by_project_id(project_id, exclude_folders_pattern="",
                                                            exclude_files_pattern="")

    # 8. create new scan, will get a scan id
    print("8. create new scan, will get a scan id")
    scan = scan_api.create_new_scan(project_id=project_id)
    scan_id = scan.id
    print("scan_id : {}".format(scan_id))

    # 9. get scan details by scan id
    print("9. get scan details by scan id")
    while True:
        scan_detail = scan_api.get_sast_scan_details_by_scan_id(scan_id=scan_id)
        scan_status = scan_detail.status.name
        print("scan_status: {}".format(scan_status))
        if scan_status == "Finished":
            break
        elif scan_status == "Failed":
            return
        time.sleep(10)

    # 11[optional]. get statistics results by scan id
    print("11[optional]. get statistics results by scan id")
    statistics = scan_api.get_statistics_results_by_scan_id(scan_id=scan_id)
    if statistics:
        print(statistics)

    # 12. register scan report
    print("12. register scan report")
    report = scan_api.register_scan_report(scan_id=scan_id, report_type=report_type)
    report_id = report.report_id
    print("report_id : {}".format(report_id))

    # 13. get report status by id
    print("13. get report status by id")
    while not scan_api.is_report_generation_finished(report_id):
        time.sleep(10)

    # 14. get report by id
    print("14. get report by id")
    report_content = scan_api.get_report_by_id(report_id)

    time_stamp = datetime.now().strftime('_%Y_%m_%d_%H_%M_%S')

    file_name = normpath(join(report_folder, project_name + time_stamp + "." + report_type))
    with open(str(file_name), "wb") as f_out:
        f_out.write(report_content)
    return scan_id, report_content.decode("utf-8")


if __name__ == "__main__":

    cx_one_project_id = "b42c794e-8ae9-445f-a81c-7f0c71749a60"
    scan_id, report_content = scan_from_git(team_full_name="/CxServer",
                                            project_name="Happy-Test-demo",
                                            report_type="xml",
                                            git_repo_url="https://github.com/HappyY19/JavaVulnerableLab.git",
                                            branch="refs/heads/master",
                                            report_folder='D:\\',
                                            pat=None,
                                            )
    query_risk_dict = {}
    query_recommendation_dict = {}
    query_ids = get_all_query_ids_from_scan(scan_id)
    for query_id in query_ids:
        query_description = QueriesAPI().get_the_full_description_of_the_query(query_id=query_id)
        soup = BeautifulSoup(query_description, 'html.parser')
        query_risk = []
        query_recommendation = []
        for index, pre in enumerate(soup.find_all('pre')):
            if index < 2:
                for child in pre.descendants:
                    print(child)
                    if child.name == "p":
                        query_risk.append(child.text)
                    if child.name == "li":
                        query_risk.append(child.text)
            elif index == 2:
                for child in pre.descendants:
                    if child.name == "p":
                        query_recommendation.append(child.text)
                    if child.name == "li":
                        query_recommendation.append(child.text)
            else:
                continue
        query_risk = "\n".join(query_risk)
        query_risk_dict.update({query_id: query_risk})
        query_recommendation = "\n".join(query_recommendation)
        query_recommendation_dict.update({query_id: query_recommendation})
    sarif_result = create_sarif_report_from_sast_xml(
        xml_path=None,
        xml_string=report_content,
        query_risk_dict=query_risk_dict,
        query_recommendation_dict=query_recommendation_dict
    )
    sarif_result_dict: dict = obj_to_dict(sarif_result)
    with open('data.sarif', 'w') as f:
        json.dump(sarif_result_dict, f)
    with ZipFile('data.zip', 'w') as myzip:
        myzip.write('eggs.txt')
    url = create_a_pre_signed_url_to_upload_files()
    print("upload_url: {}".format(url))
    result = upload_zip_content_for_scanning(
        upload_link=url,
        zip_file_path=r"data.zip"
    )
    import_result = create_byor_import(
            ImportRequest(project_id=cx_one_project_id, upload_url=url)
    )
    print(f"import_id: {import_result.import_id}")
