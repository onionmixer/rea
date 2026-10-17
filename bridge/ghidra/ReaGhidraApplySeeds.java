import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Apply caller-declared analysis seeds before default auto-analysis.
 *
 * The single argument is REA's canonical seed snapshot: one
 * {@code 0x<hex>\t(function|code|label)[\tname]} or
 * {@code 0x<hex>\tfallthrough\t0x<target>} line per seed. Fallthrough seeds are applied
 * first: the single instruction at the address is decoded without following flow, the bytes
 * up to the target become data words (inline operands such as a 68000 trap parameter), the
 * instruction's fallthrough is overridden to the target, and the target is disassembled.
 * Function seeds follow (highest address first), then code, then labels. The outcome is stored
 * as a program property that the bridge reports during its handshake.
 */
public final class ReaGhidraApplySeeds extends GhidraScript {
    static final String REPORT_OPTION = "REA analysis seeds";

    private record Seed(Address address, String kind, String name) {}

    /** Function and fallthrough seed addresses: stale-decode cleanup never clears these. */
    private final Set<Address> asserted = new HashSet<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("REA seed script requires exactly one seed file");
        }
        Path path = Path.of(args[0]);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("REA seed file is not a regular file");
        }
        byte[] bytes = Files.readAllBytes(path);
        String sha256 = HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(bytes)
        );
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        List<Seed> seeds = new ArrayList<>();
        for (String line : new String(bytes, StandardCharsets.UTF_8).split("\n")) {
            if (line.isEmpty()) continue;
            String[] fields = line.split("\t", -1);
            if (fields.length < 2 || fields.length > 3 || !fields[0].startsWith("0x")) {
                throw new IllegalArgumentException("REA seed snapshot is malformed");
            }
            Address address;
            try {
                address = space.getAddress(Long.parseUnsignedLong(fields[0].substring(2), 16));
            } catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
                address = null;
            }
            seeds.add(new Seed(address, fields[1], fields.length == 3 ? fields[2] : null));
        }

        // Highest address first: a function body computed before analysis stops at
        // an existing function entry, so later creations cannot swallow earlier ones.
        seeds.sort((left, right) -> {
            if (left.address() == null) return right.address() == null ? 0 : 1;
            if (right.address() == null) return -1;
            return right.address().compareTo(left.address());
        });
        for (Seed seed : seeds) {
            if (seed.address() != null && (seed.kind().equals("function") || seed.kind().equals("fallthrough")))
                asserted.add(seed.address());
        }
        int unmapped = 0;
        int logged = 0;
        int codeDecoded = 0, codeFailed = 0;
        int functionCreated = 0, functionExisting = 0, functionFailed = 0;
        int labelApplied = 0, labelFailed = 0;
        int fallthroughApplied = 0, fallthroughFailed = 0;
        for (String pass : new String[] { "fallthrough", "function", "code", "label" }) {
            for (Seed seed : seeds) {
                if (!seed.kind().equals(pass)) continue;
                monitor.checkCancelled();
                MemoryBlock block = seed.address() == null
                    ? null
                    : currentProgram.getMemory().getBlock(seed.address());
                if (block == null || (!pass.equals("label") && !block.isInitialized())) {
                    unmapped++;
                    continue;
                }
                switch (pass) {
                    case "fallthrough" -> {
                        String failure = fallthrough(seed.address(), space, seed.name());
                        if (failure == null) fallthroughApplied++;
                        else {
                            fallthroughFailed++;
                            if (logged++ < 20) println("REA seed failed: fallthrough " + seed.address() + " " + failure);
                        }
                    }
                    case "code" -> {
                        if (decoded(seed.address())) codeDecoded++;
                        else {
                            codeFailed++;
                            if (logged++ < 20) println("REA seed failed: code " + seed.address() + " " + why(seed.address()));
                        }
                    }
                    case "function" -> {
                        Function existing = getFunctionAt(seed.address());
                        if (existing != null) {
                            functionExisting++;
                            if (seed.name() != null) {
                                existing.setName(seed.name(), SourceType.USER_DEFINED);
                            }
                        } else if (decoded(seed.address()) &&
                            createFunction(seed.address(), seed.name()) != null) {
                            functionCreated++;
                        } else {
                            functionFailed++;
                            if (logged++ < 20) println("REA seed failed: function " + seed.address() + " " + why(seed.address()));
                        }
                    }
                    default -> {
                        try {
                            createLabel(seed.address(), seed.name(), true, SourceType.USER_DEFINED);
                            labelApplied++;
                        } catch (Exception e) {
                            labelFailed++;
                        }
                    }
                }
            }
        }
        String report = "{\"format\":\"rea-ghidra-seeds-v1\",\"sha256\":\"" + sha256 + "\"" +
            ",\"entries\":" + seeds.size() +
            ",\"function_created\":" + functionCreated +
            ",\"function_existing\":" + functionExisting +
            ",\"function_failed\":" + functionFailed +
            ",\"code_decoded\":" + codeDecoded +
            ",\"code_failed\":" + codeFailed +
            ",\"label_applied\":" + labelApplied +
            ",\"label_failed\":" + labelFailed +
            ",\"fallthrough_applied\":" + fallthroughApplied +
            ",\"fallthrough_failed\":" + fallthroughFailed +
            ",\"unmapped\":" + unmapped + "}";
        currentProgram.getOptions(Program.PROGRAM_INFO).setString(REPORT_OPTION, report);
        println("REA seeds applied: " + report);
    }

    private String why(Address address) {
        if (getDataAt(address) != null) return "defined data " + getDataAt(address).getDataType().getName();
        var containing = getInstructionContaining(address);
        if (containing != null && !containing.getAddress().equals(address))
            return "inside instruction at " + containing.getAddress();
        Function owner = getFunctionContaining(address);
        if (owner != null) return "inside function " + owner.getEntryPoint();
        return getInstructionAt(address) == null ? "undecodable" : "function creation refused";
    }

    /**
     * Decode the instruction at an address alone, mark the bytes up to the target as inline
     * operand words, override its fallthrough to the target and decode the continuation.
     * Returns null on success or the reason for refusing.
     */
    private String fallthrough(Address address, AddressSpace space, String targetText) throws Exception {
        Address target;
        try {
            target = space.getAddress(Long.parseUnsignedLong(targetText.substring(2), 16));
        } catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
            return "target outside the address space";
        }
        MemoryBlock targetBlock = currentProgram.getMemory().getBlock(target);
        if (targetBlock == null || !targetBlock.isInitialized()) return "target outside initialized memory";
        // Earlier preparation (for example the raw-binary entry flow) may have decoded the
        // inline operands as instructions. Those decodes contradict this caller assertion:
        // remove them until the stale chain re-aligns with the real instruction stream.
        Instruction containing = getInstructionContaining(address);
        if (containing != null && !containing.getAddress().equals(address)) {
            clearListing(containing.getAddress(), containing.getMaxAddress());
        }
        Instruction instruction = getInstructionAt(address);
        if (instruction == null) {
            if (getDataAt(address) != null)
                return why(address);
            DisassembleCommand command = new DisassembleCommand(address, new AddressSet(address), false);
            command.applyTo(currentProgram, monitor);
            instruction = getInstructionAt(address);
            if (instruction == null) return "undecodable";
        }
        Address after = instruction.getMaxAddress().next();
        if (after == null || after.compareTo(target) > 0)
            return "target lies inside the instruction ending at " + instruction.getMaxAddress();
        clearStaleChain(after, target);
        for (Address at = after; at.compareTo(target) < 0; ) {
            if (getInstructionContaining(at) != null) return "inline operand overlaps instruction at " + at;
            long remaining = target.subtract(at);
            if (getDataContaining(at) == null) {
                if (remaining >= 2) createWord(at);
                else createByte(at);
            }
            at = at.add(remaining >= 2 ? 2 : 1);
        }
        instruction.setFallThrough(target);
        if (getInstructionAt(target) == null) {
            if (getDataAt(target) != null || getInstructionContaining(target) != null)
                return "target " + target + " is not decodable: " + why(target);
            disassemble(target);
            if (getInstructionAt(target) == null) return "target " + target + " is undecodable";
        }
        return null;
    }

    /**
     * Remove decodes that contradict the asserted layout: anything inside the inline operands
     * at {@code after}..{@code target}, then anything that overlaps the real instruction stream
     * starting at {@code target} without starting on one of its boundaries. The real stream is
     * measured with the pseudo disassembler; the walk stops after four consecutive real
     * instructions without a conflict or at an instruction without fallthrough.
     */
    private void clearStaleChain(Address after, Address target) throws Exception {
        PseudoDisassembler pseudo = new PseudoDisassembler(currentProgram);
        Set<Address> boundaries = realBoundaries(pseudo, target);
        clearStaleSuccessors(after, boundaries);
        if (after.compareTo(target) < 0) clearOverlapping(after, target.subtract(1), null);
        Address real = target;
        int quiet = 0;
        for (int step = 0; step < 64 && quiet < 4; step++) {
            PseudoInstruction decoded;
            try {
                decoded = pseudo.disassemble(real);
            } catch (Exception e) {
                return;
            }
            if (decoded == null) return;
            Address last = real.add(decoded.getLength() - 1);
            quiet = clearOverlapping(real, last, decoded) ? 0 : quiet + 1;
            if (!decoded.getFlowType().hasFallthrough()) return;
            real = last.next();
            if (real == null) return;
        }
    }

    /** Start addresses of the real instruction stream from {@code start} along fallthrough. */
    private Set<Address> realBoundaries(PseudoDisassembler pseudo, Address start) {
        Set<Address> boundaries = new HashSet<>();
        Address at = start;
        for (int step = 0; step < 64 && at != null; step++) {
            boundaries.add(at);
            PseudoInstruction decoded;
            try {
                decoded = pseudo.disassemble(at);
            } catch (Exception e) {
                break;
            }
            if (decoded == null || !decoded.getFlowType().hasFallthrough()) {
                if (decoded != null) boundaries.add(at.add(decoded.getLength()));
                break;
            }
            at = at.add(decoded.getLength());
        }
        return boundaries;
    }

    /**
     * Follow the stale fallthrough chain that an earlier decode started inside the inline
     * operands and clear it until it reaches a real boundary, an asserted seed address, or its
     * own end. Bounded to 32 instructions.
     */
    private void clearStaleSuccessors(Address stale, Set<Address> boundaries) throws Exception {
        for (int step = 0; step < 32 && stale != null; step++) {
            if (boundaries.contains(stale) || asserted.contains(stale)) return;
            Instruction garbage = getInstructionContaining(stale);
            if (garbage == null) return;
            if (asserted.contains(garbage.getAddress())) return;
            Address next = garbage.getMaxAddress().next();
            boolean fallsThrough = garbage.getFlowType().hasFallthrough();
            clearListing(garbage.getAddress(), garbage.getMaxAddress());
            if (!fallsThrough) return;
            stale = next;
        }
    }

    /** Clear instructions intersecting [first, last] unless one matches {@code keep} exactly. */
    private boolean clearOverlapping(Address first, Address last, PseudoInstruction keep) throws Exception {
        boolean cleared = false;
        Instruction before = getInstructionContaining(first);
        if (before != null && !before.getAddress().equals(first)) {
            clearListing(before.getAddress(), before.getMaxAddress());
            cleared = true;
        }
        for (Address at = first; at.compareTo(last) <= 0; at = at.next()) {
            Instruction existing = getInstructionAt(at);
            if (existing == null) continue;
            boolean matches = keep != null && at.equals(first) && existing.getLength() == keep.getLength();
            if (!matches) {
                clearListing(existing.getAddress(), existing.getMaxAddress());
                cleared = true;
            }
            if (at.equals(last)) break;
        }
        return cleared;
    }

    /** Decode one instruction flow at an address, keeping an existing decode. */
    private boolean decoded(Address address) {
        if (getInstructionAt(address) != null) return true;
        if (getDataAt(address) != null || getInstructionContaining(address) != null) {
            return false;
        }
        disassemble(address);
        return getInstructionAt(address) != null;
    }
}
