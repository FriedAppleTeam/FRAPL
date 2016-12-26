#!/bin/bash

# usage:
# ./create_project.sh [project folder]
# ex: ./create_project.sh ~/Projects/NewProject

if [ $# -eq 0 ]; then
    echo "usage: ./create_project.sh [-f] [project folder]"
    echo "   -f: create minimal FridaLink client/server"
    exit
elif [ $# -eq 1 ]; then
    PROJECT_FOLDER=$1
    EXT="min"
elif [ $# -eq 2 ]; then
    OPT=$1
    if [ "$OPT" != "-f" ]; then
        exit
    fi
    EXT="frl"
    PROJECT_FOLDER=$2
fi

CURRENT_FOLDER=$(realpath ./)

mkdir $PROJECT_FOLDER
if [ $? -ne 0 ]; then
    echo "Unable to create folder: $PROJECT_FOLDER"
    exit
fi

ln -s "$CURRENT_FOLDER/FRAPL" "$PROJECT_FOLDER/FRAPL"
if [ $? -ne 0 ]; then
    echo "Unable to create symlink to FRAPL"
    exit
fi

ln -s "$CURRENT_FOLDER/node_modules" "$PROJECT_FOLDER/node_modules"
if [ $? -ne 0 ]; then
    echo "Unable to create symlink to node_modules"
    exit
fi

cp "$CURRENT_FOLDER/templates/client_$EXT.js" "$PROJECT_FOLDER/client.js"
if [ $? -ne 0 ]; then
    echo "Unable to create client script"
    exit
fi

cp "$CURRENT_FOLDER/templates/server_$EXT.js" "$PROJECT_FOLDER/server.js"
if [ $? -ne 0 ]; then
    echo "Unable to create server script"
    exit
fi

cp "$CURRENT_FOLDER/templates/theme_example.json" "$PROJECT_FOLDER/theme.json"
if [ $? -ne 0 ]; then
    echo "Unable to copy theme template"
    exit
fi
