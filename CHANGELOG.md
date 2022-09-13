# Change Log
All notable changes to this project will be documented in this file.

## 1.2.2 - 2022-09-313
This release fixes an issue with the 1.2.1 release where the `service_site_id` was not used to generate the
`admin` and `dev` tenan records.

### Breaking Changes:
- None.

### New features:
- None.

### Bug fixes:
- This release corrects the approach used in 1.2.1 to update Tenants API to use the `service_site_id` when storing 
the primary site record whenever `ensure_primary_site_present` is True. With this update, it also uses the 
`service_site_id` when storing the `admin` and `dev` tenant records.


## 1.2.1 - 2022-08-30
This release changes Tenants API to use the `service_site_id` when storing the primary site
record whenever `ensure_primary_site_present` is True.

### Breaking Changes:
- None.

### New features:
- None.

### Bug fixes:
- This release changes Tenants API to use the `service_site_id` when storing the primary site record
whenever `ensure_primary_site_present` is True. See issue #5 for more details. 


## 1.2.0 - 2022-05-30
There were no major updates in this release.

### Breaking Changes:
- None.

### New features:
- None.

### Bug fixes:
- None.


## 1.1.0 - 2022-03-01
This release converts the Tenats API to using the new `tapipy-tapisservice` plugin-based 
Tapis Python SDK and makes updates necessary for supporting deployment automation provided
by the Tapis Deployer project.

### Breaking Changes:
- None.

### New features:
- Convert Tenants API to using the new `tapis/flaskbase-plugins` image.
- Support the initial version of the Tapis Deployer deployment automation. 

### Bug fixes:
- None.


## 1.0.0 - 2021-07-31
Initial production release of the Tapis Tenants API with support for managing the sites
and tenants within a distributed Tapis installation.

For more details, please see the documentations: https://tapis.readthedocs.io/en/latest/technical/authentication.html

Live-docs: https://tapis-project.github.io/live-docs/

### Breaking Changes:
- Initial release.

### New features:
- Initial release.

### Bug fixes:
- None.


## 0.1.0 - 2019-10-20 (target)
### Added
- Initial alpha release.

### Changed
- No change.

### Removed
- No change.
