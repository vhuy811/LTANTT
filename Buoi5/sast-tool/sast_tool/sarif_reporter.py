import warnings
from sarif_om import SarifLog, Run, Tool, ToolComponent, Result, Message
from sarif_om import ArtifactLocation, Location, PhysicalLocation, Region
import jsonpickle


class SarifReporter:
    def generate_report(self, issues, output_file='report.sarif',
                        analyzed_file="input.py"):
        results = []
        for i in issues:
            results.append(Result(
                message=Message(text=i['message']),
                locations=[Location(
                    physical_location=PhysicalLocation(
                        artifact_location=ArtifactLocation(uri=analyzed_file),
                        region=Region(start_line=i['lineno'],
                                      start_column=i['col_offset'] + 1)
                    )
                )]
            ))

        run = Run(
            tool=Tool(driver=ToolComponent(name="PySAST", version="1.0.0")),
            results=results
        )
        log = SarifLog(schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
                       version="2.1.0", runs=[run])

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            encoded = jsonpickle.encode(log, unpicklable=False, indent=2)
        with open(output_file, 'w') as f:
            f.write(encoded)
