#!/bin/bash

echo "Reassembling database from parts ..."
cat inthewild.db.part* > inthewild.db
echo "Done"
