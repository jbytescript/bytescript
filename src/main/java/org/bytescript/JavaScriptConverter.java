package org.bytescript;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Date;
import java.util.Stack;

import org.apache.bcel.Constants;
import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.classfile.Code;
import org.apache.bcel.classfile.ConstantFieldref;
import org.apache.bcel.classfile.ConstantMethodref;
import org.apache.bcel.classfile.ConstantNameAndType;
import org.apache.bcel.classfile.ConstantPool;
import org.apache.bcel.classfile.ConstantValue;
import org.apache.bcel.classfile.Field;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.LocalVariable;
import org.apache.bcel.classfile.LocalVariableTable;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.classfile.Utility;
import org.apache.bcel.generic.BasicType;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.util.ByteSequence;
import org.apache.bcel.util.ClassPath;

/**
 * Derived from example code at http://bcel.sourceforge.net/JasminVisitor.java.
 *
 * @author Jonathan Fuerth <jfuerth@redhat.com>
 */
public class JavaScriptConverter {

  public JavaScriptConverter() {
  }

  public void convert(JavaClass clazz, PrintWriter out) throws IOException {
    ConstantPoolGen cp = new ConstantPoolGen(clazz.getConstantPool());

    out.println("/* Produced by bytescript on " + new Date());
    out.println(" */");

    out.println("// Source File " + clazz.getSourceFileName());
    out.println("// " + Utility.classOrInterface(clazz.getAccessFlags()) + " "
            + Utility.accessToString(clazz.getAccessFlags(), true) + " "
            + clazz.getClassName());
    out.println("// extends " + clazz.getSuperclassName());

    String[] interfaces = clazz.getInterfaceNames();

    for (int i = 0; i < interfaces.length; i++) {
      out.println("// implements " + interfaces[i]);
    }

    out.println("var " + jsClassName(clazz.getClassName()) + " = {");

    // static fields
    for (Field f : clazz.getFields()) {
      if ((f.getModifiers() & Constants.ACC_STATIC) != 0) {
        writeField(f, out);
      }
    }

    // instance fields
    out.println("  \"instanceState\": {");
    for (Field f : clazz.getFields()) {
      if ((f.getModifiers() & Constants.ACC_STATIC) == 0) {
        writeField(f, out);
      }
    }
    out.println("  },");

    for (Method m : clazz.getMethods()) {
      writeMethod(m, out);
    }

    out.println("},");
  }

  public void writeField(final Field field, final PrintWriter out) {
    out.print("  \"" + field.getName() + "\" : ");
    if (field.getType() instanceof BasicType) {
      ConstantValue constantValue = field.getConstantValue();
      if (constantValue != null) {
        out.print(constantValue); // XXX this is definitely broken
      }
      else {
        out.print("0");
      }
    }
    out.println(",");
  }

  /**
   * Writes the JavaScript method declaration and code code of the method to the given JavaScript output stream.
   *
   * @param m the method to convert to JavaScript
   * @param out The stream to write to
   */
  private void writeMethod(final Method m, final PrintWriter out) throws IOException {
    out.print("  \"" + m.getName() + m.getSignature() + "\" : function(");
    for (int i = 0; i < m.getArgumentTypes().length; i++) {
      if (i > 0) {
        out.print(", ");
      }
      out.print("a" + i);
    }
    out.println(") {");

    Code code = m.getCode();
    ByteSequence bytes = new ByteSequence(code.getCode());
    Stack<Object> operandStack = new Stack<Object>();
    while (bytes.available() > 0) {
      out.println(processByteCode(bytes, operandStack, code.getLocalVariableTable(), code.getConstantPool(), false));
    }
    out.println("  },");
  }

  /**
   * Takes one or more bytes from the given stream of bytes, returning a
   * JavaScript statement if necessary.
   * <p>
   * Note: this method was adapted from the Apache BCEL
   * {@link Utility#codeToString(ByteSequence, ConstantPool, boolean)} method.
   *
   * @param bytes
   *          a buffer of Java bytecode with its cursor positioned at the
   *          beginning of an opcode.
   * @param operandStack
   *          current contents of the bytecode interpreter's operand stack. May
   *          be modified as a result of processing the bytecode. Constant
   *          values, field references, and method references are pushed onto
   *          this stack as snippets of JavaScript code. Other values (like
   *          return addresses) may be other types, such as integers.
   * @param localVariableTable
   *          the containing method's local variable table.
   * @param cp
   *          the constant pool of the containing class.
   * @param wide
   *          always false except in the special case where this method calls
   *          itself
   */
  private String processByteCode(final ByteSequence bytes, final Stack<Object> operandStack, LocalVariableTable localVariableTable, final ConstantPool cp, final boolean wide) throws IOException {
    int default_offset = 0, low, high, npairs;
    int index, vindex, constant;
    int[] match, jump_table;
    int no_pad_bytes = 0, offset;

    short opcode = (short) bytes.readUnsignedByte();
    StringBuilder buf = new StringBuilder();
    buf.append("// ").append(Constants.OPCODE_NAMES[opcode]).append("\n");

    /* Special case: Skip (0-3) padding bytes, i.e., the
     * following bytes are 4-byte-aligned
     */
    if ((opcode == Constants.TABLESWITCH) || (opcode == Constants.LOOKUPSWITCH)) {
      int remainder = bytes.getIndex() % 4;
      no_pad_bytes = (remainder == 0) ? 0 : 4 - remainder;

      for (int i = 0; i < no_pad_bytes; i++) {
        byte b;

        if ((b = bytes.readByte()) != 0)
          System.err.println("Warning: Padding byte != 0 in " + Constants.OPCODE_NAMES[opcode] + ":" + b);
      }

      // Both cases have a field default_offset in common
      default_offset = bytes.readInt();
    }

    switch (opcode) {
    /*
     * Table switch has variable length arguments.
     */
    case Constants.TABLESWITCH:
      low = bytes.readInt();
      high = bytes.readInt();

      offset = bytes.getIndex() - 12 - no_pad_bytes - 1;
      default_offset += offset;

      buf.append("\tdefault = " + default_offset + ", low = " + low + ", high = " + high + "(");

      jump_table = new int[high - low + 1];
      for (int i = 0; i < jump_table.length; i++) {
        jump_table[i] = offset + bytes.readInt();
        buf.append(jump_table[i]);

        if (i < jump_table.length - 1)
          buf.append(", ");
      }
      buf.append(")");

      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * Lookup switch has variable length arguments.
     */
    case Constants.LOOKUPSWITCH: {

      npairs = bytes.readInt();
      offset = bytes.getIndex() - 8 - no_pad_bytes - 1;

      match = new int[npairs];
      jump_table = new int[npairs];
      default_offset += offset;

      buf.append("\tdefault = " + default_offset + ", npairs = " + npairs + " (");

      for (int i = 0; i < npairs; i++) {
        match[i] = bytes.readInt();

        jump_table[i] = offset + bytes.readInt();

        buf.append("(" + match[i] + ", " + jump_table[i] + ")");

        if (i < npairs - 1)
          buf.append(", ");
      }
      buf.append(")");

      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);

    }
      break;

    /*
     * Two address bytes + offset from start of byte stream form the jump target
     */
    case Constants.GOTO:
    case Constants.IFEQ:
    case Constants.IFGE:
    case Constants.IFGT:
    case Constants.IFLE:
    case Constants.IFLT:
    case Constants.JSR:
    case Constants.IFNE:
    case Constants.IFNONNULL:
    case Constants.IFNULL:
    case Constants.IF_ACMPEQ:
    case Constants.IF_ACMPNE:
    case Constants.IF_ICMPEQ:
    case Constants.IF_ICMPGE:
    case Constants.IF_ICMPGT:
    case Constants.IF_ICMPLE:
    case Constants.IF_ICMPLT:
    case Constants.IF_ICMPNE:
      buf.append("\t\t#" + ((bytes.getIndex() - 1) + bytes.readShort()));
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * 32-bit wide jumps
     */
    case Constants.GOTO_W:
    case Constants.JSR_W:
      buf.append("\t\t#" + ((bytes.getIndex() - 1) + bytes.readInt()));
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    case Constants.ALOAD_0:
    case Constants.DLOAD_0:
    case Constants.FLOAD_0:
    case Constants.ILOAD_0:
    case Constants.LLOAD_0:
      operandStack.push(localVariableTable.getLocalVariable(0));
      break;

    case Constants.ALOAD_1:
    case Constants.DLOAD_1:
    case Constants.FLOAD_1:
    case Constants.ILOAD_1:
    case Constants.LLOAD_1:
      operandStack.push(localVariableTable.getLocalVariable(1));
      break;

    case Constants.ALOAD_2:
    case Constants.DLOAD_2:
    case Constants.FLOAD_2:
    case Constants.ILOAD_2:
    case Constants.LLOAD_2:
      operandStack.push(localVariableTable.getLocalVariable(2));
      break;

    case Constants.ALOAD_3:
    case Constants.DLOAD_3:
    case Constants.FLOAD_3:
    case Constants.ILOAD_3:
    case Constants.LLOAD_3:
      operandStack.push(localVariableTable.getLocalVariable(3));
      break;

    /*
     * Index byte references local variable (register)
     */
    case Constants.ALOAD:
    case Constants.DLOAD:
    case Constants.FLOAD:
    case Constants.ILOAD:
    case Constants.LLOAD:
      if (wide) {
        vindex = bytes.readUnsignedShort();
      }
      else {
        vindex = bytes.readUnsignedByte();
      }
      operandStack.push(localVariableTable.getLocalVariable(vindex));
      break;

    case Constants.ASTORE:
    case Constants.DSTORE:
    case Constants.FSTORE:
    case Constants.ISTORE:
    case Constants.LSTORE:
      if (wide) {
        vindex = bytes.readUnsignedShort();
      }
      else {
        vindex = bytes.readUnsignedByte();
      }
      LocalVariable lhs = localVariableTable.getLocalVariable(vindex);
      Object rhs = operandStack.pop();
      buf.append(lhs.getName()).append(" = ").append(rhs); // FIXME need to render rhs based on its type
      break;

    case Constants.RET:
      if (wide) {
        vindex = bytes.readUnsignedShort();
      }
      else {
        vindex = bytes.readUnsignedByte();
      }
      LocalVariable address = localVariableTable.getLocalVariable(vindex);
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * The wide byte signals a 16-bit address in the following instruction.
     * We recurse with the wide param set true and return the result of processing the following opcode in wide mode.
     */
    case Constants.WIDE:
      return processByteCode(bytes, operandStack, localVariableTable, cp, true);

    /*
     * Array of basic type.
     */
    case Constants.NEWARRAY:
      buf.append("\t\t<" + Constants.TYPE_NAMES[bytes.readByte()] + ">");
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * Access object/class fields.
     */
    case Constants.GETFIELD:
      index = bytes.readUnsignedShort();
      buf.append("\t\t" + cp.constantToString(index, Constants.CONSTANT_Fieldref));
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    case Constants.GETSTATIC: {
      index = bytes.readUnsignedShort();
      ConstantFieldref fieldref = (ConstantFieldref) cp.getConstant(index, Constants.CONSTANT_Fieldref);
      ConstantNameAndType nameAndType = (ConstantNameAndType) cp.getConstant(fieldref.getNameAndTypeIndex(), Constants.CONSTANT_NameAndType);
      String fieldName = nameAndType.getName(cp);
      operandStack.push(jsClassName(fieldref.getClass(cp)) + "[\"" + fieldName + "\"]");
    }
      break;


    case Constants.PUTFIELD:
      index = bytes.readUnsignedShort();
      buf.append("\t\t" + cp.constantToString(index, Constants.CONSTANT_Fieldref));
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    case Constants.PUTSTATIC:
      index = bytes.readUnsignedShort();
      buf.append("\t\t" + cp.constantToString(index, Constants.CONSTANT_Fieldref));
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * Operands are references to classes in constant pool
     */
    case Constants.NEW:
    case Constants.CHECKCAST:
      buf.append("\t");
    case Constants.INSTANCEOF:
      index = bytes.readUnsignedShort();
      buf.append("\t<" + cp.constantToString(index, Constants.CONSTANT_Class) + ">");
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * Operands are references to methods in constant pool
     */
    case Constants.INVOKESPECIAL:
    case Constants.INVOKESTATIC: {
      index = bytes.readUnsignedShort();
      ConstantMethodref methodref = (ConstantMethodref) cp.getConstant(index, Constants.CONSTANT_Methodref);
      ConstantNameAndType methodNameAndType = (ConstantNameAndType) cp.getConstant(methodref.getNameAndTypeIndex());

      // invoke directly on the target class for special and static
      buf.append(jsClassName(methodref.getClass(cp)));
      buf.append("[\"").append(signature(methodNameAndType, cp)).append("\"](");
      String[] argTypes = Utility.methodSignatureArgumentTypes(methodNameAndType.getSignature(cp));
      for (int i = 0; i < argTypes.length; i++) {
        if (i > 0) {
          buf.append(", ");
        }
        buf.append(operandStack.pop());
      }
      buf.append(");");
    }
      break;

    case Constants.INVOKEVIRTUAL: {
      index = bytes.readUnsignedShort();
      ConstantMethodref methodref = (ConstantMethodref) cp.getConstant(index, Constants.CONSTANT_Methodref);
      ConstantNameAndType methodNameAndType = (ConstantNameAndType) cp.getConstant(methodref.getNameAndTypeIndex());

      // render name and args first, because the target object comes off the operand stack last
      String nameAndArgs = methodNameAndArgs(operandStack, cp, methodNameAndType);
      buf.append(operandStack.pop()).append(nameAndArgs);

    }
      break;

    case Constants.INVOKEINTERFACE:
      index = bytes.readUnsignedShort();
      int nargs = bytes.readUnsignedByte(); // historical, redundant
      buf.append("\t" + cp.constantToString(index, Constants.CONSTANT_InterfaceMethodref)
              + nargs + "\t" + bytes.readUnsignedByte());
      // Last byte is a reserved space
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * Operands are references to items in constant pool
     */
    case Constants.LDC_W:
    case Constants.LDC2_W:
      index = bytes.readUnsignedShort();

      buf.append("\t\t" + cp.constantToString(index, cp.getConstant(index).getTag()));
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    case Constants.LDC:
      index = bytes.readUnsignedByte();

      operandStack.push(cp.constantToString(index, cp.getConstant(index).getTag()));
      break;

    /*
     * Array of references.
     */
    case Constants.ANEWARRAY:
      index = bytes.readUnsignedShort();

      buf.append("\t\t<" + Utility.compactClassName(cp.getConstantString(index, Constants.CONSTANT_Class), false));
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * Multidimensional array of references.
     */
    case Constants.MULTIANEWARRAY: {
      index = bytes.readUnsignedShort();
      int dimensions = bytes.readUnsignedByte();

      buf.append("\t<" + Utility.compactClassName(cp.getConstantString(index, Constants.CONSTANT_Class), false)
              + ">\t" + dimensions);
    }
    if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    /*
     * Increment local variable.
     */
    case Constants.IINC:
      if (wide) {
        vindex = bytes.readUnsignedShort();
        constant = bytes.readShort();
      }
      else {
        vindex = bytes.readUnsignedByte();
        constant = bytes.readByte();
      }
      buf.append("\t\t%" + vindex + "\t" + constant);
      if (1==1) throw new RuntimeException("Not implemented: " + Constants.OPCODE_NAMES[opcode]);
      break;

    case Constants.RETURN:
      buf.append("return;");
      operandStack.clear();
      break;

    default:
      if (1==1) throw new RuntimeException("Reached default case while processing " + Constants.OPCODE_NAMES[opcode] + ". Operand count: " + Constants.NO_OF_OPERANDS[opcode]);
      if (Constants.NO_OF_OPERANDS[opcode] > 0) {
        for (int i = 0; i < Constants.TYPE_OF_OPERANDS[opcode].length; i++) {
          buf.append("\t\t");
          switch (Constants.TYPE_OF_OPERANDS[opcode][i]) {
          case Constants.T_BYTE:
            buf.append(bytes.readByte());
            break;
          case Constants.T_SHORT:
            buf.append(bytes.readShort());
            break;
          case Constants.T_INT:
            buf.append(bytes.readInt());
            break;

          default: // Never reached
            throw new AssertionError("Unreachable default case reached while processing " + Constants.OPCODE_NAMES[opcode]);
          }
        }
      }
    }

    return buf.toString();
  }

  /**
   * Renders the part of the method call that comes after the ".". The caller is
   * expected to prefix the returned string with a class name (in the case of
   * invokestatic and invokespecial) or a reference to a receiving object (in
   * the case of invokevirtual).
   *
   * @param operandStack
   *          The current operand stack. <i>n</i> values will be popped from
   *          this stack, where <i>n</i> is the number of parameters the method
   *          takes.
   * @param cp
   *          The constant pool of the containing class (the class that contains
   *          the method invocation, not the one that will receive it).
   * @param methodNameAndType
   *          The constant pool entry that references the target method's name
   *          and type.
   */
  private String methodNameAndArgs(final Stack<Object> operandStack, final ConstantPool cp,
          ConstantNameAndType methodNameAndType) {
    StringBuilder buf = new StringBuilder();
    buf.append("[\"").append(signature(methodNameAndType, cp)).append("\"](");
    String[] argTypes = Utility.methodSignatureArgumentTypes(methodNameAndType.getSignature(cp));
    for (int i = 0; i < argTypes.length; i++) {
      if (i > 0) {
        buf.append(", ");
      }
      buf.append(operandStack.pop());
    }
    buf.append(");");
    return buf.toString();
  }

  /**
   * Returns the method's name and signature in the same form as
   * {@link Method#getName()} and {@link Method#getSignature()} do. The
   * resulting string can be used to invoke the method on the target object (or
   * class).
   *
   * @param nameAndType
   *          The constant that points to the method's name and parameter
   *          signature within the constant pool.
   * @param cp
   *          The constant pool referred to by nameAndType.
   * @return The method signature.
   */
  private String signature(ConstantNameAndType nameAndType, ConstantPool cp) {
    return nameAndType.getName(cp) + nameAndType.getSignature(cp);
  }

  /**
   * Returns the name of the JavaScript variable that holds the given class's
   * definition.
   *
   * @param javaClassName
   *          Fully-qualified Java class name, in the format returned by
   *          {@link Class#getName()}.
   * @return The name of the JavaScript global variable that holds the class.
   */
  private static String jsClassName(String javaClassName) {
    return javaClassName.replace('.', '_');
  }

  public static void main(String[] argv) throws Exception {
    ClassParser parser = null;
    JavaClass javaClass;
    ClassPath classPath = new ClassPath();

    if (argv.length == 0) {
      System.err.println("disassemble: No input files specified");
    }
    else {
      for (int i = 0; i < argv.length; i++) {
        if (argv[i].endsWith(".class"))
          parser = new ClassParser(argv[i]); // Create parser object
        else {
          InputStream is = classPath.getInputStream(argv[i]);
          String name = jsClassName(argv[i]) + ".class";

          parser = new ClassParser(is, name);
        }

        javaClass = parser.parse();

        String className = javaClass.getClassName();
        int index = className.lastIndexOf('.');
        String path = className.substring(0, index + 1).replace('.', File.separatorChar);
        className = className.substring(index + 1);

        if (!path.equals("")) {
          File f = new File(path);
          f.mkdirs();
        }

        PrintWriter out = new PrintWriter(path + className + ".js");
        try {
          new JavaScriptConverter().convert(javaClass, out);
        }
        finally {
          out.close();
        }
      }
    }
  }

}