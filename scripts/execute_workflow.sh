#!/bin/bash

ACTION=$1
PROJECT=$2
PROJECT_URL=$3

PROJECTS_DIR=projects

PROJECT_DIR=${PROJECTS_DIR}/${PROJECT}

ORIGINAL_SRC=${PROJECT_DIR}/original_source
HUMAN_ANNOTATED=${PROJECT_DIR}/human_annotated
INTERMEDIATE_FILES=${PROJECT_DIR}/intermediate_files

ANNOTATOR=src/annotator.py
COMMENT_EXTRACTOR=src/utils/comment_extractor.py
README=asset/README.MD

function create_dirs {
    # Create the directories
    mkdir -p ${PROJECT_DIR}
    mkdir -p ${ORIGINAL_SRC} ${HUMAN_ANNOTATED} ${INTERMEDIATE_FILES}
    cp asset/README.MD ${PROJECT_DIR}
    
    # TODO: Might have code in specific subdirectories so best if users did that for now.
    # Clone the source
    echo "Run the below command and keep the bpf directory only, deleting others"
    echo "git clone --depth=1 ${PROJECT_URL} ${ORIGINAL_SRC} && rm -rf ${ORIGINAL_SRC}/.git && cd ${ORIGINAL_SRC}"
}

function annotate_project {
    # Run annotator
    python3 ${ANNOTATOR} -o ${INTERMEDIATE_FILES}/${PROJECT} -s ${ORIGINAL_SRC} -c ${HUMAN_ANNOTATED} \
        -t ${INTERMEDIATE_FILES}/${PROJECT}.function_file_list.json -u ${INTERMEDIATE_FILES}/${PROJECT}.struct_file_list.json \
        -p ${PROJECT}
}

function extract_comments {
    python3 ${COMMENT_EXTRACTOR} -s ${HUMAN_ANNOTATED} -d  ${HUMAN_ANNOTATED}/${PROJECT}.db_comments.db
}

ACTION=${1}

if [ "${ACTION}" = "create_dirs" ];
then
    create_dirs
elif [ "${ACTION}" = "annotate" ];
then
    annotate_project
elif [ "${ACTION}" = "extract_comment" ];
then
    extract_comments
else
    echo "USAGE ./scripts/execute_workflow.sh <create_dirs/annotate/extract_comment> <project> <project-git>"
fi
