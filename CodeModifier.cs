using System.ComponentModel.Design;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace Analyzer
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            const string testFileToParse = @"C:\Users\sakib\RiderProjects\Analyzer\Test.cs";
            var filetoParse = @"D:\Research\SanAndreasUnity\Assets\Scripts\Behaviours\Weapon.cs";
            const string targetClass = "Weapon";
            const string targetField = "AmmoInClip";
            var fileContent = File.ReadAllText(filetoParse);
            var syntaxTree = CSharpSyntaxTree.ParseText(fileContent);
            var root = syntaxTree.GetRoot();

            MemberDeclarationSyntax mds = null;
            ClassDeclarationSyntax cds = null;
            ClassDeclarationSyntax cdsNew = null;

            foreach (var classDeclaration in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
            {
                if (classDeclaration.Identifier.Text != targetClass) continue;
                cds = classDeclaration;
                var memberDeclarationSyntaxList = classDeclaration.Members.ToList<MemberDeclarationSyntax>();
                foreach (var memberDeclarationSyntax in memberDeclarationSyntaxList)
                {
                    if (memberDeclarationSyntax is FieldDeclarationSyntax syntax)
                    {
                        var fds = syntax;
                        if (fds.Declaration.Variables.All(variable => variable.Identifier.Text != targetField))
                            continue;
                        mds = fds;
                        break;
                    }
                    if (memberDeclarationSyntax is PropertyDeclarationSyntax syn)
                    {
                        var pds = syn;
                        if (pds.Identifier.Text != targetField) continue;
                        mds = pds;
                        break;
                    }
                }
                if (mds == null) continue;
                FieldDeclarationSyntax aField = SF.FieldDeclaration(
                            SF.VariableDeclaration(
                                SF.ParseTypeName("int"),
                                SF.SeparatedList(new[] { SF.VariableDeclarator(SF.Identifier(" _a = 159")) })
                            ))
                        .AddModifiers(mds.Modifiers.ToArray())
                        .AddAttributeLists(mds.AttributeLists.ToArray());
                cdsNew = classDeclaration.InsertNodesBefore(mds, new List<SyntaxNode> {aField});
                break;
            }
            
            root = root.ReplaceNode(cds, cdsNew);

            Console.WriteLine(root.ToString());

        }
    }
}