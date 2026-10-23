"""CLI entry point for Image Forensics Analyzer."""

import sys
import os

# Add parent directory to path for direct execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
from colorama import init as colorama_init
from pathlib import Path

from image_forensics.core.extractor import MetadataExtractor
from image_forensics.core.analyzer import ForensicAnalyzer
from image_forensics.core.hasher import FileHasher
from image_forensics.core.reporter import ReportGenerator
from image_forensics.utils.file_utils import get_image_files, get_file_info
from image_forensics.utils.geo_utils import format_gps_coordinates
from image_forensics import __version__

colorama_init(autoreset=True)


@click.group()
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx):
    """Image Metadata Extraction and Analysis System for Digital Forensic Investigation."""
    ctx.ensure_object(dict)
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--recursive', '-r', is_flag=True, help='Process directories recursively')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', 'output_format', type=click.Choice(['json', 'table', 'csv']), default='table', help='Output format')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode (no output)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def extract(path, recursive, output, output_format, quiet, verbose):
    """Extract metadata from image(s)."""
    extractor = MetadataExtractor(verbose=verbose)
    results = []

    path_obj = Path(path)

    if path_obj.is_file():
        if not quiet:
            click.echo(f"Extracting metadata from: {path}")
        result = extractor.extract(path)
        results.append(result)
    elif path_obj.is_dir():
        image_files = get_image_files(path, recursive=recursive)
        if not quiet:
            click.echo(f"Found {len(image_files)} image(s)")

        for img_path in image_files:
            if not quiet:
                click.echo(f"Processing: {img_path}")
            try:
                result = extractor.extract(str(img_path))
                results.append(result)
            except Exception as e:
                if verbose:
                    click.echo(f"Error processing {img_path}: {e}")

    if output:
        generator = ReportGenerator()
        if output_format == 'json':
            generator.save_json(results, output)
        elif output_format == 'csv':
            generator.save_csv(results, output)
        click.echo(f"Results saved to: {output}")
    else:
        for result in results:
            display_extraction_result(result, output_format)


def display_extraction_result(result, output_format):
    """Display extraction result in specified format."""
    if output_format == 'table':
        click.echo(f"\n{'='*60}")
        click.echo(f"File: {result['filename']}")
        click.echo(f"{'='*60}")

        if result.get('error'):
            click.secho(f"Error: {result['error']}", fg='red')
            return

        if result.get('basic_info'):
            click.echo("\n[Basic Information]")
            for key, value in result['basic_info'].items():
                click.echo(f"  {key}: {value}")

        if result.get('exif'):
            click.echo("\n[EXIF Data]")
            for key, value in result['exif'].items():
                click.echo(f"  {key}: {value}")

        if result.get('gps'):
            click.echo("\n[GPS Data]")
            for key, value in result['gps'].items():
                click.echo(f"  {key}: {value}")

        if result.get('iptc'):
            click.echo("\n[IPTC Data]")
            for key, value in result['iptc'].items():
                click.echo(f"  {key}: {value}")

        if result.get('software'):
            click.echo("\n[Software/Processing]")
            for key, value in result['software'].items():
                click.echo(f"  {key}: {value}")

    elif output_format == 'json':
        import json
        click.echo(json.dumps(result, indent=2, default=str))


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(path, quiet, verbose):
    """Run forensic analysis on image metadata."""
    if not quiet:
        click.echo(f"Analyzing: {path}")

    extractor = MetadataExtractor(verbose=verbose)
    analyzer = ForensicAnalyzer(verbose=verbose)

    metadata = extractor.extract(path)
    analysis = analyzer.analyze(metadata)

    if not quiet:
        display_analysis_result(analysis, verbose)
    else:
        import json
        click.echo(json.dumps(analysis, indent=2, default=str))


def display_analysis_result(analysis, verbose):
    """Display forensic analysis result."""
    click.echo(f"\n{'='*60}")
    click.echo(f"Forensic Analysis Report")
    click.echo(f"{'='*60}")

    click.echo(f"\nFile: {analysis.get('filename', 'N/A')}")
    click.echo(f"Overall Risk Level: ", nl=False)

    risk = analysis.get('risk_level', 'unknown')
    if risk == 'critical':
        click.secho("CRITICAL", fg='red', bold=True)
    elif risk == 'high':
        click.secho("HIGH", fg='red')
    elif risk == 'medium':
        click.secho("MEDIUM", fg='yellow')
    elif risk == 'low':
        click.secho("LOW", fg='green')
    else:
        click.secho("UNKNOWN", fg='white')

    if analysis.get('anomalies'):
        click.echo(f"\n[Anomalies Detected]")
        for anomaly in analysis['anomalies']:
            severity = anomaly.get('severity', 'info')
            if severity == 'critical':
                color = 'red'
            elif severity == 'high':
                color = 'red'
            elif severity == 'medium':
                color = 'yellow'
            else:
                color = 'cyan'

            click.secho(f"  [{severity.upper()}] ", fg=color, nl=False)
            click.echo(f"{anomaly['type']}: {anomaly['description']}")

    if analysis.get('findings'):
        click.echo(f"\n[Findings]")
        for finding in analysis['findings']:
            click.echo(f"  - {finding}")

    if verbose and analysis.get('metadata_summary'):
        click.echo(f"\n[Metadata Summary]")
        for key, value in analysis['metadata_summary'].items():
            click.echo(f"  {key}: {value}")


@cli.command()
@click.argument('path1', type=click.Path(exists=True))
@click.argument('path2', type=click.Path(exists=True))
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
def compare(path1, path2, quiet):
    """Compare metadata between two images."""
    extractor = MetadataExtractor()
    hasher = FileHasher()

    meta1 = extractor.extract(path1)
    meta2 = extractor.extract(path2)

    hash1 = hasher.hash_file(path1)
    hash2 = hasher.hash_file(path2)

    display_comparison(path1, path2, meta1, meta2, hash1, hash2, quiet)


def display_comparison(path1, path2, meta1, meta2, hash1, hash2, quiet):
    """Display comparison result."""
    click.echo(f"\n{'='*60}")
    click.echo(f"Metadata Comparison")
    click.echo(f"{'='*60}")

    click.echo(f"\nFile 1: {path1}")
    click.echo(f"File 2: {path2}")

    # Hash comparison
    click.echo(f"\n[File Hashes]")
    click.echo(f"  File 1 SHA256: {hash1['sha256']}")
    click.echo(f"  File 2 SHA256: {hash2['sha256']}")

    if hash1['sha256'] == hash2['sha256']:
        click.secho("  Files are IDENTICAL", fg='green')
    else:
        click.secho("  Files are DIFFERENT", fg='yellow')

    # EXIF comparison
    exif1 = meta1.get('exif', {})
    exif2 = meta2.get('exif', {})

    common_keys = set(exif1.keys()) & set(exif2.keys())
    diff_keys = [k for k in common_keys if exif1[k] != exif2[k]]

    if diff_keys:
        click.echo(f"\n[Different EXIF Values]")
        for key in diff_keys:
            click.echo(f"  {key}:")
            click.echo(f"    File 1: {exif1[key]}")
            click.echo(f"    File 2: {exif2[key]}")

    # Missing keys
    only_in_1 = set(exif1.keys()) - set(exif2.keys())
    only_in_2 = set(exif2.keys()) - set(exif1.keys())

    if only_in_1:
        click.echo(f"\n[Only in File 1]")
        for key in only_in_1:
            click.echo(f"  {key}: {exif1[key]}")

    if only_in_2:
        click.echo(f"\n[Only in File 2]")
        for key in only_in_2:
            click.echo(f"  {key}: {exif2[key]}")


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), required=True, help='Output file path')
@click.option('--format', '-f', 'report_format', type=click.Choice(['json', 'html', 'csv']), default='json', help='Report format')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
def report(path, output, report_format, quiet):
    """Generate forensic report."""
    extractor = MetadataExtractor()
    analyzer = ForensicAnalyzer()
    generator = ReportGenerator()
    hasher = FileHasher()

    metadata = extractor.extract(path)
    analysis = analyzer.analyze(metadata)
    hashes = hasher.hash_file(path)

    report_data = {
        'metadata': metadata,
        'analysis': analysis,
        'hashes': hashes
    }

    if report_format == 'html':
        generator.generate_html_report(report_data, output)
    elif report_format == 'json':
        generator.save_json(report_data, output)
    elif report_format == 'csv':
        generator.save_csv([metadata], output)

    if not quiet:
        click.secho(f"Report saved to: {output}", fg='green')


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--hashes', '-H', multiple=True, type=click.Choice(['md5', 'sha1', 'sha256', 'sha512']), help='Hash algorithms to compute')
@click.option('--output', '-o', type=click.Path(), help='Output file')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
def hash(path, hashes, output, quiet):
    """Calculate file hashes."""
    hasher = FileHasher()

    if not hashes:
        hashes = ('md5', 'sha1', 'sha256', 'sha512')

    results = hasher.hash_file(path, list(hashes))

    if output:
        import json
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        if not quiet:
            click.secho(f"Hashes saved to: {output}", fg='green')
    else:
        for algo, hash_value in results.items():
            click.echo(f"{algo.upper()}: {hash_value}")


def main():
    """Entry point."""
    cli(obj={})


if __name__ == '__main__':
    main()