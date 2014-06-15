## Synopsis

A Python client for connecting to VMWare SRM (Site Recovery Manager 5.0) via its SOAP API and performing recovery operations.

## Motivation

VMWare SRM provides SDKs for Java and .NET, but its documentation is not very helpful if you want to use
its SOAP API from other programming languages. The instructions on how to log in are particularly unclear.
To make things even more confusing, obsolete API methods from SRM v1.0 are listed alongside the current
methods from SRM v5.0.

This project solves these challenges by providing a very lightweight and easy to understand implementation of an SRM client.
The client connects to an SRM server and performs recovery operations, and can be used from the command line or from your
own Python code.

SRM client does not implement every API method provided by SRM, but rather aims to wrap the low-level API methods into
higher level operations.

## Usage

After building the project you can run SRM commands using the bin/srm executable.

    % bin/srm
    Usage:
        srm list-plans    <hostname> <username> <password> [--debug]
        srm test          <plan-name> <hostname> <username> <password> [--debug]
        srm cleanupTest   <plan-name> <hostname> <username> <password> [--debug]
        srm failover      <plan-name> <hostname> <username> <password> [--debug]
        srm reprotect     <plan-name> <hostname> <username> <password> [--debug]
        srm revert        <plan-name> <hostname> <username> <password> [--debug]
        srm cancel        <plan-name> <hostname> <username> <password> [--debug]
        srm show-result   <plan-name> <hostname> <username> <password> [--debug]

## Code Example

It is also possible to import SrmClient and use it from your code:

    from srm_client.client import SrmClient
    with SrmClient('srm01', 'administrator', 'password123').open() as client:
        print client.get_recovery_plans()

## Building the Project

Run the following commands:

    easy_install -U infi.projector
    projector devenv build --use-isolated-python

## Implementation Notes

We have chosen to refrain from using SOAP in the "formal" way. Instead, we generate the SOAP XML requests using Jinja2 templates, and simply
POST them to the SRM server. This keeps things very lightweight, and makes it very clear what is sent to the server (see the contents of the templates directory).

The response XML is parsed using xmltodict which makes it very easy to pluck the information that we need. Here too we chose simplicity over formality.

## References

* [SRM API Documentation](https://www.vmware.com/support/developer/srm-api/)
* [Jinja2](http://jinja.pocoo.org/docs/)
* [xmltodict](https://github.com/martinblech/xmltodict)
