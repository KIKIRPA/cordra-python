cordra-python: Python Client for Cordra
========================================

.. image:: https://img.shields.io/pypi/v/cordra-python
   :target: https://pypi.org/project/cordra-python/
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/pyversions/cordra-python
   :target: https://pypi.org/project/cordra-python/
   :alt: Python Versions

.. image:: https://img.shields.io/pypi/l/cordra-python
   :target: https://opensource.org/licenses/MIT
   :alt: License

A comprehensive Python library for interacting with Cordra digital object repositories via both REST API and DOIP API.

⚠️ **Important Notice**
=======================

This package is developed and maintained by the Royal Institute for Cultural Heritage (KIK-IRPA) and is not affiliated with or endorsed by the Corporation for National Research Initiatives (CNRI), the original developers of Cordra.

This package has been developed for and tested on Cordra version 2.5.2. While it may work with other versions, compatibility is not guaranteed.

Features
========

- **Dual API Support**: Choose between REST API or DOIP API based on your needs
- **Complete Authentication**: Support for password, JWT and private key authentication
- **Type Method Support**: Call custom JavaScript methods on objects and types
- **Batch Operations**: Upload multiple objects efficiently
- **Version Management**: Create and manage object versions
- **Relationship Queries**: Navigate object relationships
- **Comprehensive Error Handling**: Detailed exceptions for different error types
- **Type Hints**: Full type annotations for better IDE support

Quick Start
===========

Installation
------------

.. code-block:: bash

   pip install cordra-python

Basic Usage
-----------

.. code-block:: python

   from cordra import CordraClient

   # Initialize client
   client = CordraClient("https://cordra.example.com")

   # Authenticate
   client.authenticate(username="your_username", password="your_password")

   # Create an object
   obj = client.create_object(
       type="Document",
       content={
           "title": "My Document",
           "description": "A sample document"
       }
   )

   # Search for objects
   results = client.search("type:Document")

   # Call a type method
   result = client.call_method(
       method="extractName",
       object_id=obj.id
   )

API Reference
=============

.. automodule:: cordra
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: cordra.client
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: cordra.models
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: cordra.auth
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: cordra.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

Error Handling
==============

The library provides detailed exception classes that map to specific HTTP status codes:

.. automodule:: cordra.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
