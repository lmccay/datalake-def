#!/usr/bin/env python
import sys
sys.path.insert(1, 'aws')
sys.path.insert(2, 'azure')
sys.path.insert(3, 'gcp')
import cmd2, argparse, yaml, os, shutil, aws, azure, gcp

class CloudFactory:
    """A cloud factory"""

    def __init__(self, factory=None):
        """cloud_factory is our abstract factory.  We can set it at will."""
        self.cloud_factory = factory

    def build(self, ddf):
        """Generates IAM artifacts for cloud using the abstract factory"""
        cloud = self.cloud_factory()
        print("Cloud Type: {}".format(cloud))
        print("Vendor: {}".format(cloud.vendor()))
        cloud.build(ddf)

    @staticmethod
    def instance(self, cloudname):
        if (cloudname == "AWS"):
            from aws import AWSFactory
            factory = CloudFactory(AWSFactory)
        elif (cloudname == "Azure"):
            from azure import AzureFactory
            factory = CloudFactory(AzureFactory)
        elif (cloudname == "GCP"):
            from gcp import GCPFactory
            factory = CloudFactory(GCPFactory)
        return factory

class GCPFactory:
    def vendor(self):
        return "Google"

    def __str__(self):
        return "GCP"

