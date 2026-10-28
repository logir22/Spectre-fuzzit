// pointer_taint.sc - SPECTRE taint traversal for C/C++
//
// Finds dataflows from attacker-controlled sources (stdin, network, argv,
// getenv, scanf, ...) into memory-unsafe sinks (memcpy, strcpy, sprintf,
// system, ...) using Joern's inter-procedural dataflow engine.
//
// Usage (via joern_node.py):
//   joern --script pointer_taint.sc --params cpgFile=/path/cpg.bin,outFile=/path/out.json
//
// Output: a JSON array printed to stdout (and optionally written to outFile):
//   [{"id":"...","label":"taint","method":"...","file":"...","line":12,
//     "source":"getenv(\"PATH\")","sink":"memcpy(buf, env, n)"}]

@main def exec(cpgFile: String, outFile: String): Unit = {
  import io.shiftleft.semanticcpg.language._
  import io.joern.dataflowengineoss.queryengine.EngineContext
  import io.circe.Json

  loadCpg(cpgFile)
  implicit val context: EngineContext = EngineContext()

  // Attacker-controlled input entry points.
  val sourceNames: Set[String] = Set(
    "gets", "scanf", "__isoc99_scanf", "fscanf", "sscanf", "vscanf",
    "read", "recv", "recvfrom", "readv", "getenv", "getcwd", "readline",
    "fgets", "getchar", "fgetc", "atoi", "atol", "strtol", "argv", "argc"
  )

  // Memory-unsafe / dangerous sinks.
  val sinkNames: Set[String] = Set(
    "memcpy", "memmove", "strcpy", "strcat", "sprintf", "vsprintf",
    "snprintf", "strncpy", "strncat", "gets", "system", "popen",
    "execl", "execlp", "execv", "execvp", "execve", "dlopen", "strtok",
    "memset", "bcopy", "strdup", "realloc", "malloc", "free"
  )

  val sources = cpg.call.filter(c => sourceNames.contains(c.name)).argument
  val sinks   = cpg.call.filter(c => sinkNames.contains(c.name)).argument

  val flows = sinks.reachableByFlows(sources).l

  val json = Json.arr(
    flows.map { flow =>
      val elems = flow.elements.l
      val src = elems.head
      val snk = elems.last
      Json.obj(
        "id"     -> Json.fromString(java.lang.Integer.toHexString(flow.hashCode)),
        "label"  -> Json.fromString("taint"),
        "method" -> Json.fromString(snk.method.fullName.headOption.getOrElse("")),
        "file"   -> Json.fromString(snk.file.name.headOption.getOrElse("")),
        "line"   -> snk.lineNumber.map(n => Json.fromInt(n.toInt)).getOrElse(Json.Null),
        "source" -> Json.fromString(src.code),
        "sink"   -> Json.fromString(snk.code)
      )
    }: _*
  )

  val output = json.noSpaces

  if (outFile != null && outFile.nonEmpty) {
    val writer = new java.io.PrintWriter(outFile, "UTF-8")
    try writer.write(output)
    finally writer.close()
  }

  println(output)
}
