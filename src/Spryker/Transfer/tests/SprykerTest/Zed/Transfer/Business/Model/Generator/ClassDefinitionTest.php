<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Transfer\Business\Model\Generator;

use Codeception\Test\Unit;
use Spryker\Zed\Transfer\Business\Model\Generator\ClassDefinition;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Transfer
 * @group Business
 * @group Model
 * @group Generator
 * @group ClassDefinitionTest
 * Add your own group annotations below this line
 */
class ClassDefinitionTest extends Unit
{
    /**
     * @return void
     */
    public function testGetNameShouldReturnNormalizedTransferName()
    {
        $transferDefinition = [
            'name' => 'name',
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);
        $this->assertSame('NameTransfer', $classDefinition->getName());
    }

    /**
     * @return void
     */
    public function testIfOnePropertyIsSetGetPropertiesShouldReturnArrayWithOneProperty()
    {
        $property = $this->getProperty('property1', 'string');
        $transferDefinition = [
            'name' => 'name',
            'property' => [$property],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $properties = $classDefinition->getProperties();
        $this->assertTrue(is_array($properties));

        $given = $properties['property1'];
        $expected = $this->getProperty('property1', 'string|null');
        $this->assertEquals($expected, $given);
    }

    /**
     * @param string $name
     * @param string $type
     * @param string|null $singular
     * @param string|null $return
     * @param array $bundles
     *
     * @return array
     */
    private function getProperty($name, $type, $singular = null, $return = null, array $bundles = [])
    {
        $property = [
            'name' => $name,
            'type' => ($return === null) ? $type : $return,
            'bundles' => $bundles,
            'is_typed_array' => false,
        ];

        if ($singular !== null) {
            $property['singular'] = $singular;
        }

        return $property;
    }

    /**
     * @return void
     */
    public function testIfMoreThenOnePropertyIsSetGetPropertiesShouldReturnArrayWithAllProperties()
    {
        $transferDefinition = [
            'name' => 'name',
            'property' => [
                $this->getProperty('property1', 'string'),
                $this->getProperty('property2', 'string'),
            ],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $properties = $classDefinition->getProperties();
        $this->assertTrue(is_array($properties));

        $givenProperty = $properties['property1'];
        $expectedProperty = $this->getProperty('property1', 'string|null');
        $this->assertEquals($expectedProperty, $givenProperty);

        $givenProperty = $properties['property2'];
        $expectedProperty = $this->getProperty('property2', 'string|null');
        $this->assertEquals($expectedProperty, $givenProperty);
    }

    /**
     * @return void
     */
    public function testIfPropertyTypeIsArrayWithNameShouldBeMarkedAsArray()
    {
        $transferDefinition = [
            'name' => 'name',
            'property' => [$this->getProperty('property1', 'array')],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $properties = $classDefinition->getProperties();
        $givenProperty = $properties['property1'];
        $expectedProperty = $this->getProperty('property1', 'array');
        $this->assertEquals($expectedProperty, $givenProperty);
    }

    /**
     * @return void
     */
    public function testIfPropertyNameIsCapitalizedNameShouldBeNormalized()
    {
        $transferDefinition = [
            'name' => 'name',
            'property' => [$this->getProperty('Property1', 'array')],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $properties = $classDefinition->getProperties();
        $givenProperty = $properties['property1'];
        $expectedProperty = $this->getProperty('property1', 'array');
        $this->assertEquals($expectedProperty, $givenProperty);
    }

    /**
     * @return void
     */
    public function testIfPropertyTypeIsCollectionTheReturnTypeShouldBeAnArrayObject()
    {
        $transferDefinition = [
            'name' => 'name',
            'property' => [$this->getProperty('property1', 'Type[]')],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $properties = $classDefinition->getProperties();
        $givenProperty = $properties['property1'];
        $expectedProperty = $this->getProperty('property1', 'Type[]', null, '\ArrayObject|\Generated\Shared\Transfer\TypeTransfer[]');
        $this->assertEquals($expectedProperty, $givenProperty);
    }

    /**
     * @return void
     */
    public function testIfPropertyTypeIsTransferObjectTheReturnTypeShouldBeTransferObject()
    {
        $property = $this->getProperty('property1', 'Type');

        $transferDefinition = [
            'name' => 'name',
            'property' => [$property],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $properties = $classDefinition->getProperties();
        $givenProperty = $properties['property1'];
        $expectedProperty = $this->getProperty('property1', 'Type', null, '\Generated\Shared\Transfer\TypeTransfer|null');
        $this->assertEquals($expectedProperty, $givenProperty);
    }

    /**
     * @return void
     */
    public function testSimplePropertyShouldHaveOnlyGetterAndSetter()
    {
        $transferDefinition = [
            'name' => 'name',
            'property' => [$this->getProperty('property1', 'string')],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $methods = $classDefinition->getMethods();

        $givenSetter = $methods['setProperty1'];
        $expectedSetter = $this->getMethod('setProperty1', 'property1', 'string|null', null, null, 'PROPERTY1', [], false);
        $this->assertEquals($expectedSetter, $givenSetter);

        $givenGetter = $methods['getProperty1'];
        $expectedGetter = $this->getGetMethod('getProperty1', 'property1', null, 'string|null', null, 'PROPERTY1');
        $this->assertEquals($expectedGetter, $givenGetter);
    }

    /**
     * @return void
     */
    public function testSimpleStringPropertyShouldHaveOnlySetterWithoutTypeHint()
    {
        $transferDefinition = [
            'name' => 'name',
            'property' => [$this->getProperty('property1', 'string')],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $methods = $classDefinition->getMethods();
        $givenSetter = $methods['setProperty1'];
        $expectedSetter = $this->getMethod('setProperty1', 'property1', 'string|null', null, null, 'PROPERTY1', [], false);

        $this->assertEquals($expectedSetter, $givenSetter);
    }

    /**
     * @return void
     */
    public function testCollectionPropertyShouldHaveOnlySetterWithTypeAsTypeHint()
    {
        $transferDefinition = [
            'name' => 'name',
            'property' => [$this->getProperty('property1', 'Type[]')],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $methods = $classDefinition->getMethods();
        $givenSetter = $methods['setProperty1'];
        $expectedSetter = $this->getMethod('setProperty1', 'property1', '\ArrayObject|\Generated\Shared\Transfer\TypeTransfer[]', null, 'ArrayObject', 'PROPERTY1', [], false);

        $this->assertEquals($expectedSetter, $givenSetter);
    }

    /**
     * @return void
     */
    public function testCollectionPropertyShouldHaveGetSetAndAdd()
    {
        $bundles = ['Bundle1'];

        $transferDefinition = [
            'name' => 'name',
            'property' => [$this->getProperty('property1', 'Type[]', null, null, $bundles)],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $methods = $classDefinition->getMethods();
        $given = $methods['setProperty1'];
        $expected = $this->getMethod('setProperty1', 'property1', '\\ArrayObject|\Generated\Shared\Transfer\TypeTransfer[]', null, 'ArrayObject', 'PROPERTY1', $bundles, false);
        $this->assertEquals($expected, $given);

        $given = $methods['getProperty1'];
        $expected = $this->getGetMethod('getProperty1', 'property1', null, '\\ArrayObject|\Generated\Shared\Transfer\TypeTransfer[]', null, 'PROPERTY1', $bundles);
        $this->assertEquals($expected, $given);

        $given = $methods['addProperty1'];
        $expected = $this->getCollectionMethod('addProperty1', 'property1', 'property1', '\Generated\Shared\Transfer\TypeTransfer', null, 'TypeTransfer', 'PROPERTY1', $bundles);
        $this->assertEquals($expected, $given);
    }

    /**
     * @return void
     */
    public function testTypedArray()
    {
        $bundles = ['Bundle1'];

        $transferDefinition = [
            'name' => 'name',
            'property' => [$this->getProperty('property1', 'string[]', null, null, $bundles)],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $properties = $classDefinition->getProperties();

        $expected = [
            "property1" => [
                "name" => "property1",
                "type" => "string[]",
                "is_typed_array" => true,
                "bundles" => [
                    "Bundle1",
                ],
            ],
        ];
        $this->assertSame($expected, $properties);
    }

    /**
     * @return void
     */
    public function testCollectionPropertyWithSingularDefinitionShouldHaveAddWithDefinedName()
    {
        $property = $this->getProperty('properties', 'Type[]', 'property');

        $transferDefinition = [
            'name' => 'name',
            'property' => [$property],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);

        $methods = $classDefinition->getMethods();
        $given = $methods['setProperties'];
        $expected = $this->getMethod('setProperties', 'properties', '\\ArrayObject|\Generated\Shared\Transfer\TypeTransfer[]', null, 'ArrayObject', 'PROPERTIES', [], false);
        $this->assertEquals($expected, $given);

        $given = $methods['getProperties'];
        $expected = $this->getGetMethod('getProperties', 'properties', null, '\\ArrayObject|\Generated\Shared\Transfer\TypeTransfer[]', null, 'PROPERTIES');
        $this->assertEquals($expected, $given);

        $given = $methods['addProperty'];
        $expected = $this->getCollectionMethod('addProperty', 'property', 'properties', '\Generated\Shared\Transfer\TypeTransfer', null, 'TypeTransfer', 'PROPERTIES');
        $this->assertEquals($expected, $given);
    }

    /**
     * @param string $method
     * @param string $property
     * @param string|null $var
     * @param string|null $return
     * @param string|null $typeHint
     * @param string|null $constant
     * @param array $bundles
     * @param bool|null $hasDefaultNull
     *
     * @return array
     */
    private function getMethod($method, $property, $var = null, $return = null, $typeHint = null, $constant = null, array $bundles = [], $hasDefaultNull = null)
    {
        $method = [
            'name' => $method,
            'property' => $property,
            'bundles' => $bundles,
            'deprecationDescription' => null,
        ];

        if ($var !== null) {
            $method['var'] = $var;
        }

        if ($return !== null) {
            $method['return'] = $return;
        }

        $method['typeHint'] = $typeHint;

        if ($constant !== null) {
            $method['propertyConst'] = $constant;
        }

        if ($hasDefaultNull !== null) {
            $method['hasDefaultNull'] = $hasDefaultNull;
        }

        return $method;
    }

    /**
     * @param string $method
     * @param string $property
     * @param string|null $var
     * @param string|null $return
     * @param string|null $typeHint
     * @param string|null $constant
     * @param array $bundles
     * @param bool|null $hasDefaultNull
     *
     * @return array
     */
    private function getGetMethod($method, $property, $var = null, $return = null, $typeHint = null, $constant = null, array $bundles = [], $hasDefaultNull = null)
    {
        $method = $this->getMethod($method, $property, $var, $return, $typeHint, $constant, $bundles, $hasDefaultNull);
        unset($method['typeHint']);

        return $method;
    }

    /**
     * @param string $method
     * @param string $property
     * @param string $parent
     * @param string|null $var
     * @param string|null $return
     * @param string|null $typeHint
     * @param string|null $constant
     * @param array $bundles
     *
     * @return array
     */
    private function getCollectionMethod($method, $property, $parent, $var = null, $return = null, $typeHint = null, $constant = null, array $bundles = [])
    {
        $method = $this->getMethod($method, $property, $var, $return, $typeHint, $constant, $bundles);
        $method['parent'] = $parent;

        return $method;
    }

    /**
     * @expectedException \Spryker\Zed\Transfer\Business\Exception\InvalidNameException
     *
     * @return void
     */
    public function testInvalidPropertyNameShouldThrowException()
    {
        $property = $this->getProperty('invalid_property_name', 'string');

        $transferDefinition = [
            'name' => 'name',
            'property' => [$property],
        ];

        $classDefinition = new ClassDefinition();
        $classDefinition->setDefinition($transferDefinition);
    }
}
