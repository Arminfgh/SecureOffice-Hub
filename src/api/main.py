"""
FastAPI Main Application
REST API for ThreatScope threat intelligence platform
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
from typing import Dict

from src.config.settings import get_settings
from src.api.routes import threats, analysis, search
from src.core.threat_graph import ThreatGraph
from src.core.bloom_filter import MalwareHashFilter
from src.ai.analyzer import ThreatAnalyzer


settings = get_settings()

# Global instances
threat_graph = None
malware_filter = None
ai_analyzer = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    global threat_graph, malware_filter, ai_analyzer
    
    # Startup
    print("🚀 Starting ThreatScope API...")
    
    # Initialize core components
    threat_graph = ThreatGraph()
    malware_filter = MalwareHashFilter(expected_hashes=1000000)
    ai_analyzer = ThreatAnalyzer()
    
    print("✅ Core components initialized")
    
    # Load pre-existing data if available
    try:
        # Load malware hashes
        malware_filter.import_from_file('data/threat_feeds/malware_hashes.txt')
        print(f"📊 Loaded malware hashes: {malware_filter.get_stats()['malware_hashes']}")
    except FileNotFoundError:
        print("⚠️  No malware hash file found, starting fresh")
    
    yield
    
    # Shutdown
    print("🛑 Shutting down ThreatScope API...")


# Create FastAPI app
app = FastAPI(
    title="ThreatScope API",
    description="AI-Powered Threat Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS.split(",") if settings.CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency to get global instances
def get_threat_graph():
    return threat_graph


def get_malware_filter():
    return malware_filter


def get_ai_analyzer():
    return ai_analyzer


# Include routers
app.include_router(
    threats.router,
    prefix="/api/threats",
    tags=["Threats"]
)

app.include_router(
    analysis.router,
    prefix="/api/analyze",
    tags=["Analysis"]
)

app.include_router(
    search.router,
    prefix="/api/search",
    tags=["Search"]
)


@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "name": "ThreatScope API",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
        "endpoints": {
            "threats": "/api/threats",
            "analysis": "/api/analyze",
            "search": "/api/search"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    graph_stats = threat_graph.get_stats() if threat_graph else {}
    filter_stats = malware_filter.get_stats() if malware_filter else {}
    
    return {
        "status": "healthy",
        "components": {
            "threat_graph": {
                "status": "operational",
                "stats": graph_stats
            },
            "malware_filter": {
                "status": "operational",
                "stats": filter_stats
            },
            "ai_analyzer": {
                "status": "operational" if ai_analyzer else "unavailable"
            }
        }
    }


@app.get("/stats")
async def get_stats(
    graph: ThreatGraph = Depends(get_threat_graph),
    mf: MalwareHashFilter = Depends(get_malware_filter)
):
    """Get platform statistics"""
    return {
        "graph": graph.get_stats(),
        "malware_filter": mf.get_stats(),
        "api_version": "1.0.0"
    }


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "status_code": 500
        }
    )


if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.API_RELOAD
    )