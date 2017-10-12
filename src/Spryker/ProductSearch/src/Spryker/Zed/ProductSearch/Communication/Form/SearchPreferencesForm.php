<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSearch\Communication\Form;

use Symfony\Component\Form\CallbackTransformer;
use Symfony\Component\Form\FormBuilderInterface;

class SearchPreferencesForm extends AbstractAttributeKeyForm
{
    const FIELD_ID_PRODUCT_ATTRIBUTE_KEY = 'idProductAttributeKey';
    const FIELD_FULL_TEXT = 'fullText';
    const FIELD_FULL_TEXT_BOOSTED = 'fullTextBoosted';
    const FIELD_SUGGESTION_TERMS = 'suggestionTerms';
    const FIELD_COMPLETION_TERMS = 'completionTerms';

    /**
     * @return string
     */
    public function getName()
    {
        return 'searchPreferences';
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this
            ->addIdProductAttributeKeyField($builder)
            ->addKeyField($builder, $options)
            ->addFullTextField($builder)
            ->addFullTextBoostedField($builder)
            ->addSuggestionTermsField($builder)
            ->addCompletionTermsField($builder);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIdProductAttributeKeyField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_ID_PRODUCT_ATTRIBUTE_KEY, 'hidden');

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return $this
     */
    protected function addKeyField(FormBuilderInterface $builder, array $options)
    {
        $builder->add(self::FIELD_KEY, 'text', [
            'label' => 'Attribute key',
            'constraints' => $this->createAttributeKeyFieldConstraints(),
            'disabled' => $options[self::OPTION_IS_UPDATE],
        ]);

        return $this;
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    protected function isUniqueKey($key)
    {
        $keyCount = $this->productSearchQueryContainer
            ->queryProductAttributeKey()
            ->joinSpyProductSearchAttributeMap()
            ->filterByKey($key)
            ->count();

        return ($keyCount === 0);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addFullTextField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_FULL_TEXT, 'choice', [
            'choices' => $this->getYesNoChoices(),
        ]);

        $this->addBoolModelTransformer($builder, self::FIELD_FULL_TEXT);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addFullTextBoostedField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_FULL_TEXT_BOOSTED, 'choice', [
            'choices' => $this->getYesNoChoices(),
        ]);

        $this->addBoolModelTransformer($builder, self::FIELD_FULL_TEXT_BOOSTED);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addSuggestionTermsField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_SUGGESTION_TERMS, 'choice', [
            'choices' => $this->getYesNoChoices(),
        ]);

        $this->addBoolModelTransformer($builder, self::FIELD_SUGGESTION_TERMS);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addCompletionTermsField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_COMPLETION_TERMS, 'choice', [
            'choices' => $this->getYesNoChoices(),
        ]);

        $this->addBoolModelTransformer($builder, self::FIELD_COMPLETION_TERMS);

        return $this;
    }

    /**
     * @return array
     */
    protected function getYesNoChoices()
    {
        return [
            'no' => 'No',
            'yes' => 'Yes',
        ];
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param string $fieldName
     *
     * @return void
     */
    protected function addBoolModelTransformer(FormBuilderInterface $builder, $fieldName)
    {
        $builder->get($fieldName)->addModelTransformer(new CallbackTransformer(
            function ($originalValue) {
                return $originalValue ? 'yes' : 'no';
            },
            function ($submittedValue) {
                return $submittedValue === 'yes' ? true : false;
            }
        ));
    }
}
