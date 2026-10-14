# JLens — Windows Jump List Forensic Analyzer

JLens is a Python-based digital forensic analysis tool designed to examine Windows Jump List artifacts and generate structured PDF forensic reports.

## Overview

Windows Jump Lists can provide information about applications and files accessed by a user. JLens analyzes supported Jump List artifacts to assist investigators in examining historical user activity.

The tool also supports analysis of supported forensic disk image formats and can generate reports containing extracted and interpreted artifact information.

## Features

* Windows Automatic and Custom Jump List parsing
* Link (LNK) artifact extraction and analysis
* Application ID (AppID) resolution and classification
* File path reconstruction and artifact correlation
* Timeline generation
* Support for selected EWF/E01 forensic disk images
* Support for raw disk images
* Live-system Jump List analysis
* PDF forensic report generation
* Command-line and graphical interfaces

*Feature availability and format support should be verified against the current implementation and tested samples.*

## Technology Stack

* Python
* Tkinter for the graphical interface
* ReportLab for PDF report generation
* olefile for OLE file parsing
* PyInstaller for Windows executable packaging

The project also contains an optional integration with `pytsk3` for filesystem analysis.

## Requirements

* Windows for the graphical interface and live-system functionality
* A compatible Python installation for running from source
* Required Python dependencies
* Sufficient storage and memory for the forensic image being analyzed

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/JLens.git
cd JLens
```

Install the required dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the application:

```bash
python JLens.py
```

## Command-Line Usage

Analyze a supported forensic image:

```bash
python JLens.py --image "C:\Evidence\disk.E01" --output "report.pdf"
```

Specify analyst and case information:

```bash
python JLens.py --image "C:\Evidence\disk.E01" --output "report.pdf" --analyst "Forensic Analyst" --case "CASE-001"
```

Analyze the current Windows system:

```bash
python JLens.py --live
```

Launch the graphical interface:

```bash
python JLens.py --gui
```

The exact behavior and supported formats should be verified against the current implementation.

## Building the Windows Executable

The project includes a PyInstaller build script and specification file.

Install the required build dependencies and run:

```bash
python build_exe.py
```

The executable is expected to be generated in the `dist` directory when the build succeeds.

## Forensic Considerations

* Work on forensic copies or appropriately protected evidence.
* Preserve the original evidence and follow the applicable evidence-handling procedure.
* Validate parser results against known test artifacts.
* Record tool versions and relevant processing parameters.
* Review generated reports before relying on their findings.
* Treat reconstructed paths and inferred artifact information as interpretations that may require corroboration.

## Limitations

Results depend on artifact availability, filesystem structures, supported file formats, parser implementation, and the condition of the examined data.

The tool should be validated against known-good test cases before being used in an actual investigation.

## Disclaimer

JLens is intended for authorized digital forensic analysis, research, and educational purposes.

This software should not be treated as a substitute for validated forensic procedures, independent verification, or professional judgment.

## License

The license for this project will be specified in the repository.
