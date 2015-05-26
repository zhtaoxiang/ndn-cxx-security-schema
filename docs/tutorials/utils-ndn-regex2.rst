NDN Regular Expression
======================

NDN regular expression matching is done at two levels: one at the name
level and one at the name component level.

We use ``<`` and ``>`` to enclose a name component matcher which
specifies the pattern of a name component. The component pattern is
expressed using the `Perl Regular Expression
Syntax <http://www.boost.org/doc/libs/1_55_0/libs/regex/doc/html/boost_regex/syntax/perl_syntax.html>`__.
For example, ``<ab*c>`` can match the 1st, 3rd, and 4th components of
``/ac/dc/abc/abbc``, but it cannot match the 2nd component. A special
case is that ``<>`` is a wildcard matcher that can match **ANY**
component.

Note that a component match can match only one name component. In order
to match a name, you need to specify the pattern of a name based on the
name component matchers. For example, ``<ndn><edu><ucla>`` can match the
name ``/ndn/edu/ucla``. In order to describe a more complicated name
pattern, we borrow some syntaxes from the standard regular expressions.

NDN Regex Syntax
----------------

Repeats
~~~~~~~

A component matcher can be followed by a repeat syntax to indicate how
many times the preceding component can be matched.

Syntax ``*`` for zero or more times. For example,
``<ndn><KEY><>*<ID-CERT>`` shall match ``/ndn/KEY/ID-CERT/``, or
``/ndn/KEY/edu/ID-CERT``, or ``/ndn/KEY/edu/ksk-12345/ID-CERT`` and so
on.

Syntax ``+`` for one or more times. For example,
``<ndn><KEY><>+<ID-CERT>`` shall match ``/ndn/KEY/edu/ID-CERT``, or
``/ndn/KEY/edu/ksk-12345/ID-CERT`` and so on, but it cannot match
``/ndn/KEY/ID-CERT/``.

Syntax ``?`` for zero or one times. For example,
``<ndn><KEY><>?<ID-CERT>`` shall match ``/ndn/KEY/ID-CERT/``, or
``/ndn/KEY/edu/ID-CERT``, but it cannot match
``/ndn/KEY/edu/ksk-12345/ID-CERT``.

Repetition can also be bounded:

``{n}`` for exactly ``n`` times. ``{n,}`` for at least ``n`` times.
``{,n}`` for at most ``n`` times. And ``{n, m}`` for ``n`` to ``m``
times.

Note that the repeat matching is **greedy**, that is it will consume as
many matched components as possible. We do not support non-greedy repeat
matching and possessive repeat matching for now.

Wildcard Specializer
~~~~~~~~~~~~~~~~~~

Wildcard Specializer is an extension to set. It is a bracket-expression starting
with ``'['`` and ending with ``']'``, the content inside the brackets could be
either component set or a function name.

**Component Set** matches any single name component that is a member of that set.
Unlike the standard regular expression, NDN regular expression only supports
**Single Components Set**, that is, you have to list all the set members one by
one between the bracket. For example, ``[<ndn><localhost>]`` shall match a name
component of either ``ndn"`` or ``localhost``.

When a name component set starts with a ``'^'``, the set becomes a
**Negation Set**, that is, it matches the complement of the name
components it contains. For example, ``[^<ndn>]`` shall match any name component
except ``ndn``.

Some other types of sets, such as Range Set, will be supported later.

**Function** specializes the pattern of a component. For example, ``[digest]``
shall match a digest component. ``[timestamp]`` shall match
timestamp-format component.

Note that wildcard specializer can be repeated.

Sub-pattern and Back Reference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A section beginning ``(`` and ending ``)`` acts as a marked sub-pattern.
Whatever matched the sub-pattern is split out in a separate field by the
matching algorithms. For example ``([^<DNS>])<DNS>(<>*)<NS><>*`` shall
match a data name of NDN DNS NS record, and the first sub-pattern
captures the zone name while the second sub-pattern captures the
relative record name.

Marked sub-patterns can be referred to by a back-reference ``$n``. The
same example above shall match a name
``/ndn/edu/ucla/DNS/irl/NS/123456``, and a back reference ``$1$2`` shall
extract ``/ndn/edu/ucla/irl`` out of the name.

.. note::
    **Marked sub-patterns CANNOT be repeated**

    **Marked sub-patterns are NOT allowed inside a component matcher**

Pattern Inference
---------------------

NDN Regular Experssion also support pattern inference from original pattern.
Pattern Inference to derive patterns of original regex pattern with additional
knowledge. A list of arguments are required, the number of which should be equal
to the number of marked sub-patterns in the original pattern. The regex will
match its marked sub-patterns with these arguments so a more specific pattern
could be derived.

There are two types of arguments: **Name**, **null**.

**Name** is an NDN name, it will replace the relevant sub-pattern with an exact
pattern. For example, if the original pattern is ``<ndn><edu>(<>)(<>*)`` and
["/ucla", "/irl"] is passed to it. The inferred pattern would be
``<ndn><edu><ucla><irl>``.

**null** corresponds to an empty name, it will remove the sub-pattern. For
example, if the original pattern is ``<ndn><edu>(<>)(<>*)`` and
["/ucla", "null"] is passed to it. The inferred pattern would be
``<ndn><edu><ucla>``.

Name Derivation
--------------------

When a pattern only consists of determinate components and wildcard
specializers, an exact name could be derived from the pattern. If the wildcard
specializer is component set, name derived would randomly take any satisfied
component at that position. If the wildcard specializer is a function, the
relavant component would be generated by calling the function.

For example, name derivation of pattern ``<ndn><edu><ucla><irl>[timestamp]``
would act like
::
   Name("/ndn/edu/ucla/irl").appendTimestamp()
