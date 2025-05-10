#!/bin/bash
source ../common/for_reviewers.sh

./make_csv_redis.sh > result_${reviewer_id}/redis.csv
./make_csv_liblinear.sh > result_${reviewer_id}/liblinear.csv
./make_csv_graph500.sh > result_${reviewer_id}/graph500.csv

python3 plot_fig12.py $reviewer_id
python3 plot_fig13.py $reviewer_id
python3 plot_fig14.py $reviewer_id
