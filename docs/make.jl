using Documenter, AzSessions

makedocs(sitename="AzSessions", modules=[AzSessions])

deploydocs(
    repo = "github.com/ChevronETC/AzSessions.jl.git",
)
