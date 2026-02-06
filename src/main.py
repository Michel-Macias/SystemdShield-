#!/usr/bin/env python3
"""
SystemdShield - Automated Systemd Service Hardening
"""
import os
import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

# Disable rich markup for Typer to avoid compatibility issues
app = typer.Typer(
    help="SystemdShield: Automated systemd service hardening tool",
    no_args_is_help=True,
    add_completion=False
)
console = Console()

# Add path to import modules
sys.path.insert(0, str(Path(__file__).parent))

from analyzer import SystemdAnalyzer
from hardening import HardeningEngine


def require_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        console.print("[bold red]❌ This command requires root privileges.[/bold red]")
        console.print("Please run with: sudo python3 src/main.py <command>")
        raise typer.Exit(code=1)


@app.command()
def audit(
    threshold: float = typer.Option(8.0, help="Minimum exposure score to report"),
    show_all: bool = typer.Option(False, "--all", help="Show all services, not just high-exposure")
):
    """
    Audit all systemd services and show security exposure levels.
    """
    console.print("[bold cyan]🔍 SystemdShield Security Audit[/bold cyan]\n")
    
    analyzer = SystemdAnalyzer()
    
    if show_all:
        services = [analyzer.analyze_service(s) for s in analyzer.get_all_services()]
        services = [s for s in services if s is not None]
    else:
        services = analyzer.get_high_exposure_services(threshold)
    
    if not services:
        console.print(f"[green]✅ No services found with exposure >= {threshold}[/green]")
        return
    
    # Create table
    table = Table(title=f"Services with Exposure >= {threshold}")
    table.add_column("Service", style="cyan")
    table.add_column("Score", justify="right", style="magenta")
    table.add_column("Level", style="yellow")
    table.add_column("Status", style="green")
    
    for service in services:
        status = "🟢 Active" if service.is_active else "⚫ Inactive"
        level_color = {
            "UNSAFE": "bold red",
            "EXPOSED": "yellow",
            "MEDIUM": "blue",
            "OK": "green"
        }.get(service.exposure_level or "", "white")
        
        table.add_row(
            service.name,
            f"{service.exposure_score:.1f}" if service.exposure_score else "N/A",
            f"[{level_color}]{service.exposure_level}[/{level_color}]",
            status
        )
    
    console.print(table)
    console.print(f"\n[bold]Total: {len(services)} services[/bold]")


@app.command()
def harden(
    service: Optional[str] = typer.Argument(None, help="Service name to harden"),
    profile: Optional[str] = typer.Option(None, "--profile", help="Force specific profile"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive mode"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without applying"),
    batch: bool = typer.Option(False, "--batch", help="Harden all high-exposure services"),
    threshold: float = typer.Option(8.0, help="Exposure threshold for batch mode")
):
    """
    Apply hardening to systemd services.
    """
    require_root()
    
    config_dir = Path(__file__).parent.parent / "config"
    engine = HardeningEngine(config_dir)
    analyzer = SystemdAnalyzer()
    
    if batch:
        console.print("[bold cyan]📦 Batch Hardening Mode[/bold cyan]\n")
        services = analyzer.get_high_exposure_services(threshold)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Hardening services...", total=len(services))
            
            for svc in services:
                if engine.is_excluded(svc.name):
                    console.print(f"⏭️  Skipping excluded service: {svc.name}")
                    progress.advance(task)
                    continue
                
                result = engine.apply_hardening(svc.name, dry_run=dry_run)
                
                if result.success:
                    improvement = ""
                    if result.previous_score and result.new_score:
                        improvement = f" ({result.previous_score:.1f} → {result.new_score:.1f})"
                    console.print(f"[green]✅ {svc.name}{improvement}[/green]")
                else:
                    console.print(f"[red]❌ {svc.name}: {result.error}[/red]")
                
                progress.advance(task)
        
        return
    
    if not service:
        console.print("[red]Error: Specify a service or use --batch mode[/red]")
        raise typer.Exit(code=1)
    
    # Single service mode
    console.print(f"[bold cyan]🛡️  Hardening {service}[/bold cyan]\n")
    
    if interactive:
        # Show current status
        analysis = analyzer.analyze_service(service)
        if analysis:
            console.print(f"Current exposure: [yellow]{analysis.exposure_score} {analysis.exposure_level}[/yellow]")
        
        # Get recommended profile
        recommended = engine.get_profile_for_service(service)
        console.print(f"Recommended profile: [cyan]{recommended}[/cyan]")
        
        if not typer.confirm("Proceed with hardening?"):
            console.print("[yellow]Cancelled.[/yellow]")
            return
    
    result = engine.apply_hardening(service, profile, dry_run=dry_run)
    
    if result.success:
        if dry_run:
            console.print("[green]✅ Dry run successful. No changes made.[/green]")
        else:
            improvement = ""
            if result.previous_score and result.new_score:
                improvement = f" ({result.previous_score:.1f} → {result.new_score:.1f})"
            console.print(f"[green]✅ Successfully hardened {service}{improvement}[/green]")
            console.print(f"Profile applied: [cyan]{result.profile_applied}[/cyan]\n")
            
            # --- PANEL EDUCATIVO ---
            from rich.panel import Panel
            from models import ProfilesConfig
            import yaml
            
            # Cargar el perfil para obtener las directivas aplicadas
            with open(config_dir / "profiles.yaml") as f:
                p_cfg = ProfilesConfig(**yaml.safe_load(f))
            
            applied_profile = p_cfg.profiles.get(result.profile_applied)
            if applied_profile:
                explanations = applied_profile.overrides.get_explanations()
                
                edu_text = ""
                for directive, explanation in explanations.items():
                    edu_text += f"[bold blue]{directive}[/bold blue]: {explanation}\n"
                
                console.print(Panel(
                    edu_text.strip(),
                    title="🎓 ¿Qué hemos aprendido?",
                    subtitle="Explicación técnica de las medidas aplicadas",
                    border_style="cyan"
                ))
    else:
        console.print(f"[red]❌ Failed to harden {service}[/red]")
        console.print(f"Error: {result.error}")
        if result.rollback_performed:
            console.print("[yellow]⚠️  Automatic rollback was performed.[/yellow]")


@app.command()
def revert(
    service: str = typer.Argument(..., help="Service to revert")
):
    """
    Revert hardening changes for a service.
    """
    require_root()
    
    config_dir = Path(__file__).parent.parent / "config"
    engine = HardeningEngine(config_dir)
    
    console.print(f"[yellow]🔄 Reverting hardening for {service}[/yellow]")
    engine.rollback(service)


if __name__ == "__main__":
    app()
